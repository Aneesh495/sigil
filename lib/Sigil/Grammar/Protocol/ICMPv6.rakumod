# Sigil::Grammar::Protocol::ICMPv6 - Internet Control Message Protocol v6 dissector (RFC 4443)
#
# Parses ICMPv6 error messages, Echo request/reply, and IPv6 Neighbor Discovery (NDP)
# protocol frames including Neighbor Solicitations and Advertisements (RFC 4861).

unit class Sigil::Grammar::Protocol::ICMPv6;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing ICMPv6 message
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base ICMPv6 header requires 8 bytes
    if $buf.remaining < 8 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("ICMPv6"),
            :display-name("ICMPv6 (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("ICMPv6 message truncated: expected at least 8 bytes for header")
        );
    }

    my $start-offset = $buf.offset;
    my $type = $buf.read-uint8();
    my $code = $buf.read-uint8();
    my $checksum = $buf.read-uint16-be();

    my %type-names = (
        1   => "Destination Unreachable",
        2   => "Packet Too Big",
        3   => "Time Exceeded",
        4   => "Parameter Problem",
        128 => "Echo Request",
        129 => "Echo Reply",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        137 => "Redirect Message"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::EnumField.new(
        :name("Type"),
        :key("icmpv6.type"),
        :offset-bytes(0),
        :length-bytes(1),
        :value($type),
        :name-map(%type-names)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Code"),
        :key("icmpv6.code"),
        :offset-bytes(1),
        :length-bytes(1),
        :value($code)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Checksum"),
        :key("icmpv6.checksum"),
        :offset-bytes(2),
        :length-bytes(2),
        :value($checksum),
        :radix("hex"),
        :bit-width(16)
    ));

    my $header-len = 8;
    my $summary-extra = "";

    # Type-specific field parsing
    if $type == (128 | 129) { # Echo Request or Reply
        my $id = $buf.read-uint16-be();
        my $seq = $buf.read-uint16-be();

        $fl.add(Sigil::Core::IntField.new(
            :name("Identifier"),
            :key("icmpv6.ident"),
            :offset-bytes(4),
            :length-bytes(2),
            :value($id)
        ));

        $fl.add(Sigil::Core::IntField.new(
            :name("Sequence Number"),
            :key("icmpv6.seq"),
            :offset-bytes(6),
            :length-bytes(2),
            :value($seq)
        ));

        $summary-extra = sprintf("id=0x%04x, seq=%d", $id, $seq);
    } elsif $type == 2 { # Packet Too Big
        my $mtu = $buf.read-uint32-be();
        $fl.add(Sigil::Core::IntField.new(
            :name("MTU"),
            :key("icmpv6.mtu"),
            :offset-bytes(4),
            :length-bytes(4),
            :value($mtu)
        ));
        $summary-extra = sprintf("MTU=%d", $mtu);
    } elsif $type == (135 | 136) && $buf.remaining >= 20 { # Neighbor Solicitation / Advertisement
        if $type == 135 { # Neighbor Solicitation
            $buf.skip(4); # Reserved
            my $target-ip = $buf.read-ipv6();
            $fl.add(Sigil::Core::AddressField.new(
                :name("Target IPv6 Address"),
                :key("icmpv6.ndp.target"),
                :offset-bytes(8),
                :length-bytes(16),
                :value($target-ip),
                :address-type("ipv6")
            ));
            $header-len = 24;
            $summary-extra = sprintf("Target=%s", $target-ip);
        } else { # Neighbor Advertisement
            my $flags = $buf.read-uint32-be();
            my $r-flag = ($flags +> 31) +& 0x01; # Router flag
            my $s-flag = ($flags +> 30) +& 0x01; # Solicited flag
            my $o-flag = ($flags +> 29) +& 0x01; # Override flag
            my $target-ip = $buf.read-ipv6();

            $fl.add(Sigil::Core::FlagField.new(
                :name("Router Flag (R)"),
                :key("icmpv6.ndp.flag.router"),
                :offset-bytes(4),
                :length-bytes(4),
                :mask(0x80000000),
                :is-set($r-flag == 1)
            ));

            $fl.add(Sigil::Core::FlagField.new(
                :name("Solicited Flag (S)"),
                :key("icmpv6.ndp.flag.solicited"),
                :offset-bytes(4),
                :length-bytes(4),
                :mask(0x40000000),
                :is-set($s-flag == 1)
            ));

            $fl.add(Sigil::Core::FlagField.new(
                :name("Override Flag (O)"),
                :key("icmpv6.ndp.flag.override"),
                :offset-bytes(4),
                :length-bytes(4),
                :mask(0x20000000),
                :is-set($o-flag == 1)
            ));

            $fl.add(Sigil::Core::AddressField.new(
                :name("Target IPv6 Address"),
                :key("icmpv6.ndp.target"),
                :offset-bytes(8),
                :length-bytes(16),
                :value($target-ip),
                :address-type("ipv6")
            ));
            $header-len = 24;
            $summary-extra = sprintf("Target=%s (R=%d, S=%d, O=%d)", $target-ip, $r-flag, $s-flag, $o-flag);
        }
    } else {
        $buf.skip(min(4, $buf.remaining));
    }

    my $raw-header = $raw.subbuf($start-offset, min($header-len, $raw.elems - $start-offset));
    my $raw-payload = $raw.elems > ($start-offset + $header-len)
        ?? $raw.subbuf($start-offset + $header-len)
        !! Buf.new;

    my $type-title = %type-names{$type} // sprintf("Type %d", $type);
    my $disp = $summary-extra ne ""
        ?? sprintf("ICMPv6 (%s, %s)", $type-title, $summary-extra)
        !! sprintf("ICMPv6 (%s)", $type-title);

    return Sigil::Core::Layer.new(
        :name("ICMPv6"),
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
