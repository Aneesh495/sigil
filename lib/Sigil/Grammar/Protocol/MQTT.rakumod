# Sigil::Grammar::Protocol::MQTT - Message Queuing Telemetry Transport dissector (OASIS MQTT)
#
# Parses MQTT v3.1.1 and v5.0 fixed headers, variable-byte remaining lengths,
# control packet types (Connect, Publish, Subscribe, Ping), QoS levels, and topic filters.

unit class Sigil::Grammar::Protocol::MQTT;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing MQTT packet
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base MQTT fixed header requires at least 2 bytes
    if $buf.remaining < 2 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("MQTT"),
            :display-name("MQTT (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("MQTT packet truncated: expected at least 2 bytes for fixed header")
        );
    }

    my $start-offset = $buf.offset;

    # Byte 0: Packet Type (4 bits), Flags (4 bits)
    my $b0 = $buf.read-uint8();
    my $msg-type = $b0 +> 4;
    my $dup-flag = ($b0 +> 3) +& 0x01;
    my $qos      = ($b0 +> 1) +& 0x03;
    my $retain   = $b0 +& 0x01;

    # Remaining Length (variable-byte integer: 1 to 4 bytes)
    my $remaining-len = 0;
    my $multiplier = 1;
    my $len-bytes-consumed = 0;

    while $buf.remaining > 0 && $len-bytes-consumed < 4 {
        my $encoded-byte = $buf.read-uint8();
        $len-bytes-consumed++;
        $remaining-len += ($encoded-byte +& 0x7F) * $multiplier;
        $multiplier *= 128;
        last if ($encoded-byte +& 0x80) == 0; # Continuation bit unset
    }

    my %msg-names = (
        1  => "CONNECT",
        2  => "CONNACK",
        3  => "PUBLISH",
        4  => "PUBACK",
        5  => "PUBREC",
        6  => "PUBREL",
        7  => "PUBCOMP",
        8  => "SUBSCRIBE",
        9  => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::EnumField.new(:name("Control Packet Type"), :key("mqtt.msgtype"), :offset-bytes(0), :length-bytes(1), :value($msg-type), :name-map(%msg-names)));
    $fl.add(Sigil::Core::FlagField.new(:name("DUP Flag"), :key("mqtt.flags.dup"), :offset-bytes(0), :length-bytes(1), :mask(0x08), :is-set($dup-flag == 1)));
    $fl.add(Sigil::Core::IntField.new(:name("QoS Level"), :key("mqtt.flags.qos"), :offset-bytes(0), :length-bytes(1), :value($qos)));
    $fl.add(Sigil::Core::FlagField.new(:name("Retain Flag"), :key("mqtt.flags.retain"), :offset-bytes(0), :length-bytes(1), :mask(0x01), :is-set($retain == 1)));
    $fl.add(Sigil::Core::IntField.new(:name("Remaining Length"), :key("mqtt.len"), :offset-bytes(1), :length-bytes($len-bytes-consumed), :value($remaining-len)));

    my $extra-info = "";

    # Parse packet-specific payload fields
    if $msg-type == 3 && $buf.remaining >= 2 { # PUBLISH
        my $topic-len = $buf.read-uint16-be();
        if $buf.remaining >= $topic-len {
            my $topic = $buf.read-ascii($topic-len);
            $fl.add(Sigil::Core::StringField.new(:name("Topic Name"), :key("mqtt.topic"), :value($topic)));
            $extra-info = "Topic=" ~ $topic;

            if $qos > 0 && $buf.remaining >= 2 {
                my $pkt-id = $buf.read-uint16-be();
                $fl.add(Sigil::Core::IntField.new(:name("Packet Identifier"), :key("mqtt.pkt_id"), :value($pkt-id)));
                $extra-info ~= sprintf(" Id=%d", $pkt-id);
            }
        }
    } elsif $msg-type == 1 && $buf.remaining >= 10 { # CONNECT
        my $proto-len = $buf.read-uint16-be();
        if $buf.remaining >= $proto-len + 4 {
            my $proto-name = $buf.read-ascii($proto-len);
            my $proto-level = $buf.read-uint8();
            my $conn-flags = $buf.read-uint8();
            my $keepalive = $buf.read-uint16-be();

            $fl.add(Sigil::Core::StringField.new(:name("Protocol Name"), :key("mqtt.protoname"), :value($proto-name)));
            $fl.add(Sigil::Core::IntField.new(:name("Protocol Level"), :key("mqtt.protolevel"), :value($proto-level)));
            $fl.add(Sigil::Core::IntField.new(:name("Keep Alive (seconds)"), :key("mqtt.keepalive"), :value($keepalive)));

            if $buf.remaining >= 2 {
                my $cid-len = $buf.read-uint16-be();
                if $buf.remaining >= $cid-len {
                    my $cid = $buf.read-ascii($cid-len);
                    $fl.add(Sigil::Core::StringField.new(:name("Client Identifier"), :key("mqtt.client_id"), :value($cid)));
                    $extra-info = "Client=" ~ $cid;
                }
            }
        }
    }

    my $header-len = $buf.offset - $start-offset;
    my $raw-header = $raw.subbuf($start-offset, $header-len);
    my $avail-payload = $raw.elems - ($start-offset + $header-len);
    my $raw-payload = $avail-payload > 0 ?? $raw.subbuf($start-offset + $header-len) !! Buf.new;

    my $type-title = %msg-names{$msg-type} // sprintf("Type %d", $msg-type);
    my $disp = $extra-info ne ""
        ?? sprintf("MQTT %s (%s, QoS=%d)", $type-title, $extra-info, $qos)
        !! sprintf("MQTT %s (QoS=%d, Len=%d)", $type-title, $qos, $remaining-len);

    return Sigil::Core::Layer.new(
        :name("MQTT"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
