# Sigil::Grammar::Protocol::VLAN - IEEE 802.1Q and 802.1ad QinQ VLAN dissector
#
# Decodes single tagged and double tagged (QinQ) VLAN encapsulations,
# extracting Priority Code Point (PCP), Drop Eligible Indicator (DEI),
# VLAN Identifier (VID), and encapsulated protocol EtherTypes.

unit class Sigil::Grammar::Protocol::VLAN;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect byte buffer positioned at VLAN tag header (TPID already identified or at TCI)
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # A VLAN header (TCI + Inner EtherType) requires 4 bytes
    if $buf.remaining < 4 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("VLAN"),
            :display-name("802.1Q VLAN (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("VLAN header truncated: expected at least 4 bytes")
        );
    }

    my $start-offset = $buf.offset;
    my $tci = $buf.read-uint16-be();
    my $inner-type = $buf.read-uint16-be();

    my $pcp = $tci +> 13;
    my $dei = ($tci +> 12) +& 0x01;
    my $vid = $tci +& 0x0FFF;

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::IntField.new(
        :name("Priority Code Point (PCP)"),
        :key("vlan.pcp"),
        :offset-bytes(0),
        :length-bytes(2),
        :value($pcp)
    ));

    $fl.add(Sigil::Core::FlagField.new(
        :name("Drop Eligible Indicator (DEI)"),
        :key("vlan.dei"),
        :offset-bytes(0),
        :length-bytes(2),
        :mask(0x1000),
        :is-set($dei == 1)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("VLAN Identifier (VID)"),
        :key("vlan.id"),
        :offset-bytes(0),
        :length-bytes(2),
        :value($vid)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Encapsulated EtherType"),
        :key("vlan.encapsulated_type"),
        :offset-bytes(2),
        :length-bytes(2),
        :value($inner-type),
        :radix("hex"),
        :bit-width(16)
    ));

    my $raw-header = $raw.subbuf($start-offset, 4);
    my $raw-payload = $raw.subbuf($start-offset + 4);

    return Sigil::Core::Layer.new(
        :name("VLAN"),
        :display-name(sprintf("802.1Q VLAN (VID: %d, PCP: %d)", $vid, $pcp)),
        :offset($offset),
        :header-length(4),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol($inner-type)
    );
}
