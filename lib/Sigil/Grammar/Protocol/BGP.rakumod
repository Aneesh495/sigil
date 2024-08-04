# Sigil::Grammar::Protocol::BGP - Border Gateway Protocol 4 dissector (RFC 4271)
#
# Parses 19-byte 16-octet synchronized marker headers, BGP message types
# (OPEN, UPDATE, NOTIFICATION, KEEPALIVE), Autonomous System numbers, and BGP Identifiers.

unit class Sigil::Grammar::Protocol::BGP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing BGP message
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base BGP header requires exactly 19 bytes (16 marker + 2 length + 1 type)
    if $buf.remaining < 19 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("BGP"),
            :display-name("BGP (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("BGP message truncated: expected at least 19 bytes for header")
        );
    }

    my $start-offset = $buf.offset;

    # 16-byte 0xFF marker synchronization verification
    my $marker = $buf.read-bytes(16);
    my $valid-marker = True;
    for 0..15 -> $i {
        if $marker[$i] != 0xFF {
            $valid-marker = False;
            last;
        }
    }

    my $length = $buf.read-uint16-be();
    my $msg-type = $buf.read-uint8();

    my %type-names = (
        1 => "OPEN",
        2 => "UPDATE",
        3 => "NOTIFICATION",
        4 => "KEEPALIVE",
        5 => "ROUTE-REFRESH"
    );

    my $status = STATUS_OK;
    my $status-detail = "";
    if !$valid-marker {
        $status = STATUS_MALFORMED;
        $status-detail = "BGP 16-octet synchronization marker invalid";
    } elsif $length < 19 {
        $status = STATUS_MALFORMED;
        $status-detail = sprintf("Invalid BGP length %d (must be at least 19 bytes)", $length);
    }

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::BytesField.new(:name("Marker"), :key("bgp.marker"), :offset-bytes(0), :length-bytes(16), :raw($marker)));
    $fl.add(Sigil::Core::IntField.new(:name("Length"), :key("bgp.length"), :offset-bytes(16), :length-bytes(2), :value($length)));
    $fl.add(Sigil::Core::EnumField.new(:name("Type"), :key("bgp.type"), :offset-bytes(18), :length-bytes(1), :value($msg-type), :name-map(%type-names)));

    my $extra-info = "";

    # Type-specific variable payload parsing
    if $msg-type == 1 && $buf.remaining >= 10 { # OPEN
        my $version = $buf.read-uint8();
        my $my-as = $buf.read-uint16-be();
        my $hold-time = $buf.read-uint16-be();
        my $bgp-id = $buf.read-ipv4();
        my $opt-param-len = $buf.read-uint8();

        $fl.add(Sigil::Core::IntField.new(:name("Version"), :key("bgp.open.version"), :value($version)));
        $fl.add(Sigil::Core::IntField.new(:name("My AS"), :key("bgp.open.as"), :value($my-as)));
        $fl.add(Sigil::Core::IntField.new(:name("Hold Time (seconds)"), :key("bgp.open.hold_time"), :value($hold-time)));
        $fl.add(Sigil::Core::AddressField.new(:name("BGP Identifier"), :key("bgp.open.id"), :value($bgp-id), :address-type("ipv4")));

        $extra-info = sprintf("AS%d, ID=%s, Hold=%ds", $my-as, $bgp-id, $hold-time);
    } elsif $msg-type == 3 && $buf.remaining >= 2 { # NOTIFICATION
        my $err-code = $buf.read-uint8();
        my $err-subcode = $buf.read-uint8();

        my %error-codes = (
            1 => "Message Header Error",
            2 => "OPEN Message Error",
            3 => "UPDATE Message Error",
            4 => "Hold Timer Expired",
            5 => "Finite State Machine Error",
            6 => "Cease"
        );

        $fl.add(Sigil::Core::EnumField.new(:name("Error Code"), :key("bgp.notify.code"), :value($err-code), :name-map(%error-codes)));
        $fl.add(Sigil::Core::IntField.new(:name("Error Subcode"), :key("bgp.notify.subcode"), :value($err-subcode)));
        $extra-info = sprintf("%s (Code %d, Subcode %d)", %error-codes{$err-code} // "Error", $err-code, $err-subcode);
    }

    my $header-len = min($length, $raw.elems - $start-offset);
    my $raw-header = $raw.subbuf($start-offset, $header-len);

    my $type-title = %type-names{$msg-type} // sprintf("Type %d", $msg-type);
    my $disp = $extra-info ne ""
        ?? sprintf("BGP %s (%s)", $type-title, $extra-info)
        !! sprintf("BGP %s (Len=%d)", $type-title, $length);

    return Sigil::Core::Layer.new(
        :name("BGP"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length(0),
        :raw-header($raw-header),
        :raw-payload(Buf.new),
        :fields($fl),
        :status($status),
        :status-detail($status-detail),
        :next-protocol(Nil)
    );
}
