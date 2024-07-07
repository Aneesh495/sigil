# Sigil::Grammar::Protocol::ICMPv4 - Internet Control Message Protocol v4 dissector (RFC 792)
#
# Parses ICMP control messages, Echo ping request/reply sequences, Destination
# Unreachable codes (Path MTU discovery), Time Exceeded diagnostics, and embedded error frames.

unit class Sigil::Grammar::Protocol::ICMPv4;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Checksum;
use Sigil::Core::Error;

# Dissect raw byte buffer containing ICMPv4 message
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base ICMPv4 header requires 8 bytes
    if $buf.remaining < 8 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("ICMPv4"),
            :display-name("ICMPv4 (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("ICMPv4 message truncated: expected at least 8 bytes for header")
        );
    }

    my $start-offset = $buf.offset;
    my $type = $buf.read-uint8();
    my $code = $buf.read-uint8();
    my $checksum = $buf.read-uint16-be();

    my %type-names = (
        0  => "Echo Reply",
        3  => "Destination Unreachable",
        4  => "Source Quench",
        5  => "Redirect",
        8  => "Echo Request",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp Request",
        14 => "Timestamp Reply",
        17 => "Address Mask Request",
        18 => "Address Mask Reply"
    );

    # Verify RFC 1071 checksum over whole ICMP message
    my $status = STATUS_OK;
    my $status-detail = "";
    my $msg-slice = $raw.subbuf($start-offset);
    if !Sigil::Core::Checksum::verify-internet-checksum($msg-slice) {
        $status = STATUS_CHECKSUM_MISMATCH;
        $status-detail = sprintf("ICMP checksum 0x%04x invalid", $checksum);
    }

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::EnumField.new(
        :name("Type"),
        :key("icmp.type"),
        :offset-bytes(0),
        :length-bytes(1),
        :value($type),
        :name-map(%type-names)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Code"),
        :key("icmp.code"),
        :offset-bytes(1),
        :length-bytes(1),
        :value($code)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Checksum"),
        :key("icmp.checksum"),
        :offset-bytes(2),
        :length-bytes(2),
        :value($checksum),
        :radix("hex"),
        :bit-width(16)
    ));

    my $header-len = 8;
    my $summary-extra = "";

    # Type-specific field parsing
    if $type == (0 | 8) { # Echo Request or Echo Reply
        my $id = $buf.read-uint16-be();
        my $seq = $buf.read-uint16-be();

        $fl.add(Sigil::Core::IntField.new(
            :name("Identifier (BE)"),
            :key("icmp.ident"),
            :offset-bytes(4),
            :length-bytes(2),
            :value($id)
        ));

        $fl.add(Sigil::Core::IntField.new(
            :name("Sequence Number (BE)"),
            :key("icmp.seq"),
            :offset-bytes(6),
            :length-bytes(2),
            :value($seq)
        ));

        $summary-extra = sprintf("id=0x%04x, seq=%d", $id, $seq);
    } elsif $type == 3 { # Destination Unreachable
        my $unused = $buf.read-uint16-be();
        my $next-mtu = $buf.read-uint16-be();

        if $code == 4 { # Fragmentation Needed (Path MTU discovery)
            $fl.add(Sigil::Core::IntField.new(
                :name("Next-Hop MTU"),
                :key("icmp.next_mtu"),
                :offset-bytes(6),
                :length-bytes(2),
                :value($next-mtu)
            ));
            $summary-extra = sprintf("Frag needed, Next MTU=%d", $next-mtu);
        } else {
            my %unreach-codes = (
                0 => "Net Unreachable",
                1 => "Host Unreachable",
                2 => "Protocol Unreachable",
                3 => "Port Unreachable",
                4 => "Fragmentation Needed",
                5 => "Source Route Failed"
            );
            $summary-extra = %unreach-codes{$code} // sprintf("Code %d", $code);
        }
    } elsif $type == 11 { # Time Exceeded
        $buf.skip(4);
        my %te-codes = (
            0 => "Time to Live exceeded in transit",
            1 => "Fragment reassembly time exceeded"
        );
        $summary-extra = %te-codes{$code} // sprintf("Code %d", $code);
    } else {
        $buf.skip(4);
    }

    my $raw-header = $raw.subbuf($start-offset, 8);
    my $raw-payload = $raw.subbuf($start-offset + 8);

    my $type-title = %type-names{$type} // sprintf("Type %d", $type);
    my $disp = $summary-extra ne ""
        ?? sprintf("ICMPv4 (%s, %s)", $type-title, $summary-extra)
        !! sprintf("ICMPv4 (%s)", $type-title);

    return Sigil::Core::Layer.new(
        :name("ICMPv4"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status($status),
        :status-detail($status-detail),
        :next-protocol(Nil)
    );
}
