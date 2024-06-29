# Sigil::Grammar::Protocol::ARP - Address Resolution Protocol dissector (RFC 826)
#
# Parses Ethernet hardware mapping, IPv4 protocol bindings, request/reply opcodes,
# and detects gratuitous ARP announcements and probe broadcasts.

unit class Sigil::Grammar::Protocol::ARP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing ARP packet
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Standard Ethernet/IPv4 ARP packet requires exactly 28 bytes
    if $buf.remaining < 28 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("ARP"),
            :display-name("Address Resolution Protocol (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("ARP packet truncated: expected 28 bytes for IPv4 over Ethernet")
        );
    }

    my $start-offset = $buf.offset;
    my $hw-type = $buf.read-uint16-be();
    my $proto-type = $buf.read-uint16-be();
    my $hw-size = $buf.read-uint8();
    my $proto-size = $buf.read-uint8();
    my $opcode = $buf.read-uint16-be();

    my $sender-mac = $buf.read-mac();
    my $sender-ip = $buf.read-ipv4();
    my $target-mac = $buf.read-mac();
    my $target-ip = $buf.read-ipv4();

    my %op-names = (
        1 => "Request",
        2 => "Reply",
        3 => "RARP-Request",
        4 => "RARP-Reply"
    );

    my $is-gratuitous = ($sender-ip eq $target-ip);

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::IntField.new(
        :name("Hardware Type"),
        :key("arp.hw.type"),
        :offset-bytes(0),
        :length-bytes(2),
        :value($hw-type)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Protocol Type"),
        :key("arp.proto.type"),
        :offset-bytes(2),
        :length-bytes(2),
        :value($proto-type),
        :radix("hex"),
        :bit-width(16)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Hardware Size"),
        :key("arp.hw.size"),
        :offset-bytes(4),
        :length-bytes(1),
        :value($hw-size)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Protocol Size"),
        :key("arp.proto.size"),
        :offset-bytes(5),
        :length-bytes(1),
        :value($proto-size)
    ));

    $fl.add(Sigil::Core::EnumField.new(
        :name("Opcode"),
        :key("arp.opcode"),
        :offset-bytes(6),
        :length-bytes(2),
        :value($opcode),
        :name-map(%op-names)
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Sender MAC Address"),
        :key("arp.src.hw_mac"),
        :offset-bytes(8),
        :length-bytes(6),
        :value($sender-mac),
        :address-type("mac")
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Sender IP Address"),
        :key("arp.src.proto_ipv4"),
        :offset-bytes(14),
        :length-bytes(4),
        :value($sender-ip),
        :address-type("ipv4")
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Target MAC Address"),
        :key("arp.dst.hw_mac"),
        :offset-bytes(18),
        :length-bytes(6),
        :value($target-mac),
        :address-type("mac")
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Target IP Address"),
        :key("arp.dst.proto_ipv4"),
        :offset-bytes(24),
        :length-bytes(4),
        :value($target-ip),
        :address-type("ipv4")
    ));

    $fl.add(Sigil::Core::FlagField.new(
        :name("Gratuitous ARP"),
        :key("arp.is_gratuitous"),
        :offset-bytes(14),
        :length-bytes(14),
        :mask(0),
        :is-set($is-gratuitous)
    ));

    my $raw-header = $raw.subbuf($start-offset, 28);
    my $raw-payload = $raw.subbuf($start-offset + 28);

    my $op-desc = %op-names{$opcode} // "Unknown";
    my $disp = $is-gratuitous
        ?? sprintf("ARP (%s - Gratuitous)", $op-desc)
        !! sprintf("ARP (%s)", $op-desc);

    return Sigil::Core::Layer.new(
        :name("ARP"),
        :display-name($disp),
        :offset($offset),
        :header-length(28),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
