# Sigil::Grammar::Protocol::IGMP - Internet Group Management Protocol (RFC 1112/2236/3376)
#
# Decodes IGMPv1, IGMPv2, and IGMPv3 multicast group membership queries, reports,
# and leave messages.

unit class Sigil::Grammar::Protocol::IGMP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Checksum;

method protocol-name(--> Str) { return "IGMP"; }

our constant IGMP_TYPE_QUERY       = 0x11;
our constant IGMP_TYPE_V1_REPORT   = 0x12;
our constant IGMP_TYPE_V2_REPORT   = 0x16;
our constant IGMP_TYPE_V2_LEAVE    = 0x17;
our constant IGMP_TYPE_V3_REPORT   = 0x22;

# Dissect IGMP message
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    if $raw.elems - $offset < 8 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("IGMP"),
            :display-name("IGMP (Truncated)"),
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

    my $type = $buf.read-uint8();
    my $max-resp = $buf.read-uint8();
    my $csum = $buf.read-uint16-be();

    my %types = (
        0x11 => "Membership Query",
        0x12 => "IGMPv1 Membership Report",
        0x16 => "IGMPv2 Membership Report",
        0x17 => "IGMPv2 Leave Group",
        0x22 => "IGMPv3 Membership Report"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::EnumField.new(:name("Type"), :key("igmp.type"), :value($type), :name-map(%types)));
    $fl.add(Sigil::Core::IntField.new(:name("Max Response Time (100ms)"), :key("igmp.max_resp_time"), :value($max-resp)));
    $fl.add(Sigil::Core::IntField.new(:name("Checksum"), :key("igmp.checksum"), :value($csum), :radix("hex"), :bit-width(16)));

    my $group-addr = "0.0.0.0";
    if $type != IGMP_TYPE_V3_REPORT {
        # IGMPv1 / IGMPv2 Group Address
        my $g0 = $buf.read-uint8();
        my $g1 = $buf.read-uint8();
        my $g2 = $buf.read-uint8();
        my $g3 = $buf.read-uint8();
        $group-addr = sprintf("%d.%d.%d.%d", $g0, $g1, $g2, $g3);
        $fl.add(Sigil::Core::AddressField.new(:name("Multicast Group Address"), :key("igmp.group_address"), :value($group-addr), :address-type("ipv4")));
    } else {
        # IGMPv3 Report (RFC 3376)
        if $buf.remaining >= 4 {
            $buf.skip(2); # Reserved
            my $num-records = $buf.read-uint16-be();
            $fl.add(Sigil::Core::IntField.new(:name("Number of Group Records"), :key("igmp.num_records"), :value($num-records)));
        }
    }

    my $header-len = $buf.offset - $start;
    my $type-title = %types{$type} // sprintf("IGMP 0x%02x", $type);
    my $disp = sprintf("%s: %s", $type-title, $group-addr);

    return Sigil::Core::Layer.new(
        :name("IGMP"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length(0),
        :raw-header($raw.subbuf($start, $header-len)),
        :raw-payload(Buf.new),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
