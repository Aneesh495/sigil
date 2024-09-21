# Sigil::Grammar::Protocol::QUIC - QUIC transport protocol dissector (RFC 9000)
#
# Decodes Long and Short packet headers, Initial/Handshake/0-RTT/Retry framing,
# and variable-length Connection IDs across UDP datagrams.

unit class Sigil::Grammar::Protocol::QUIC;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

method protocol-name(--> Str) { return "QUIC"; }

our constant QUIC_PACKET_INITIAL   = 0x00;
our constant QUIC_PACKET_0RTT      = 0x01;
our constant QUIC_PACKET_HANDSHAKE = 0x02;
our constant QUIC_PACKET_RETRY     = 0x03;

# Dissect QUIC packet
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    if $raw.elems - $offset < 5 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("QUIC"),
            :display-name("QUIC (Truncated)"),
            :offset($offset),
            :header-length($raw.elems - $offset),
            :payload-length(0),
            :raw-header($raw.subbuf($offset)),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED)
        );
    }

    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));
    my $start = $offset;

    my $first-byte = $buf.read-uint8();
    my $is-long-header = ($first-byte +& 0x80) != 0;
    my $fixed-bit = ($first-byte +& 0x40) != 0;

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::FlagField.new(:name("Header Form"), :key("quic.header_form"), :mask(0x80), :is-set($is-long-header)));
    $fl.add(Sigil::Core::FlagField.new(:name("Fixed Bit"), :key("quic.fixed_bit"), :mask(0x40), :is-set($fixed-bit)));

    my $packet-type-str = "";
    my $version-str = "";
    my $dcid-str = "";
    my $scid-str = "";

    if $is-long-header {
        # Long Header (Initial, 0-RTT, Handshake, Retry)
        my $long-type = ($first-byte +& 0x30) +> 4;
        my %long-types = (
            0x00 => "Initial",
            0x01 => "0-RTT",
            0x02 => "Handshake",
            0x03 => "Retry"
        );
        $packet-type-str = %long-types{$long-type} // "Reserved";
        $fl.add(Sigil::Core::EnumField.new(:name("Long Packet Type"), :key("quic.long.packet_type"), :value($long-type), :name-map(%long-types)));

        if $buf.remaining >= 4 {
            my $version = $buf.read-uint32-be();
            $version-str = do given $version {
                when 0x00000000 { "Version Negotiation" }
                when 0x00000001 { "QUIC v1" }
                when 0x6B333E3B { "QUIC v2" }
                default         { sprintf("0x%08x", $version) }
            };
            $fl.add(Sigil::Core::IntField.new(:name("Version"), :key("quic.version"), :value($version), :radix("hex"), :bit-width(32)));

            # Destination Connection ID
            if $buf.remaining >= 1 {
                my $dcid-len = $buf.read-uint8();
                if $buf.remaining >= $dcid-len {
                    my $dcid-bytes = $buf.read-bytes($dcid-len);
                    $dcid-str = $dcid-bytes.list.map({ sprintf("%02x", $_) }).join("");
                    $fl.add(Sigil::Core::StringField.new(:name("Destination Connection ID"), :key("quic.dcid"), :value($dcid-str)));
                }
            }

            # Source Connection ID
            if $buf.remaining >= 1 {
                my $scid-len = $buf.read-uint8();
                if $buf.remaining >= $scid-len {
                    my $scid-bytes = $buf.read-bytes($scid-len);
                    $scid-str = $scid-bytes.list.map({ sprintf("%02x", $_) }).join("");
                    $fl.add(Sigil::Core::StringField.new(:name("Source Connection ID"), :key("quic.scid"), :value($scid-str)));
                }
            }
        }
    } else {
        # Short Header (1-RTT)
        $packet-type-str = "1-RTT (Short Header)";
        my $spin-bit = ($first-byte +& 0x20) != 0;
        my $key-phase = ($first-byte +& 0x04) != 0;
        $fl.add(Sigil::Core::FlagField.new(:name("Spin Bit"), :key("quic.spin_bit"), :mask(0x20), :is-set($spin-bit)));
        $fl.add(Sigil::Core::FlagField.new(:name("Key Phase"), :key("quic.key_phase"), :mask(0x04), :is-set($key-phase)));
    }

    my $header-len = $buf.offset - $start;
    my $disp = $is-long-header
        ?? sprintf("QUIC %s (%s), DCID=%s", $packet-type-str, $version-str, $dcid-str)
        !! sprintf("QUIC %s", $packet-type-str);

    return Sigil::Core::Layer.new(
        :name("QUIC"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length($buf.remaining),
        :raw-header($raw.subbuf($start, $header-len)),
        :raw-payload($buf.read-remaining()),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
