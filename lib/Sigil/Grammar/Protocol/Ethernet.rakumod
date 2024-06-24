# Sigil::Grammar::Protocol::Ethernet - IEEE 802.3 and Ethernet II frame dissector
#
# Parses MAC destination/source addresses, 802.1Q VLAN tags, and EtherTypes.

unit class Sigil::Grammar::Protocol::Ethernet;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing Ethernet II frame
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Minimum Ethernet II frame header size is 14 bytes
    if $buf.remaining < 14 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("Ethernet"),
            :display-name("Ethernet II (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("Frame truncated: expected at least 14 bytes for Ethernet II header")
        );
    }

    my $start-offset = $buf.offset;
    my $dst-mac = $buf.read-mac();
    my $src-mac = $buf.read-mac();
    my $ethertype = $buf.read-uint16-be();

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::AddressField.new(
        :name("Destination MAC"),
        :key("eth.dst"),
        :offset-bytes(0),
        :length-bytes(6),
        :value($dst-mac),
        :address-type("mac")
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Source MAC"),
        :key("eth.src"),
        :offset-bytes(6),
        :length-bytes(6),
        :value($src-mac),
        :address-type("mac")
    ));

    my $header-len = 14;
    my $next-proto = $ethertype;

    # Handle 802.1Q single VLAN tag (0x8100)
    if $ethertype == 0x8100 && $buf.remaining >= 4 {
        my $tci = $buf.read-uint16-be();
        my $inner-type = $buf.read-uint16-be();
        my $vlan-pri = $tci +> 13;
        my $vlan-cfi = ($tci +> 12) +& 0x01;
        my $vlan-id  = $tci +& 0x0FFF;

        $fl.add(Sigil::Core::IntField.new(
            :name("VLAN Priority (PCP)"),
            :key("vlan.priority"),
            :offset-bytes(14),
            :length-bytes(2),
            :value($vlan-pri)
        ));

        $fl.add(Sigil::Core::FlagField.new(
            :name("VLAN Drop Eligible (DEI)"),
            :key("vlan.dei"),
            :offset-bytes(14),
            :length-bytes(2),
            :mask(0x1000),
            :is-set($vlan-cfi == 1)
        ));

        $fl.add(Sigil::Core::IntField.new(
            :name("VLAN Identifier (VID)"),
            :key("vlan.id"),
            :offset-bytes(14),
            :length-bytes(2),
            :value($vlan-id)
        ));

        $fl.add(Sigil::Core::IntField.new(
            :name("Inner EtherType"),
            :key("eth.type"),
            :offset-bytes(16),
            :length-bytes(2),
            :value($inner-type),
            :radix("hex"),
            :bit-width(16)
        ));

        $header-len = 18;
        $next-proto = $inner-type;
    } else {
        $fl.add(Sigil::Core::IntField.new(
            :name("EtherType"),
            :key("eth.type"),
            :offset-bytes(12),
            :length-bytes(2),
            :value($ethertype),
            :radix("hex"),
            :bit-width(16)
        ));
    }

    my $raw-header = $raw.subbuf($start-offset, $header-len);
    my $raw-payload = $raw.subbuf($start-offset + $header-len);

    return Sigil::Core::Layer.new(
        :name("Ethernet"),
        :display-name("Ethernet II"),
        :offset($offset),
        :header-length($header-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol($next-proto)
    );
}
