# Test suite for Sigil::Core::Packet
use Test;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Types;

plan 15;

my $raw_frame = Buf.new(1..64);

# Create packet
my $pkt = Sigil::Core::Packet.new(
    :raw($raw_frame),
    :packet-id(101),
    :timestamp(1700000000.123456e0),
    :wire-length(64),
    :capture-length(64),
    :interface("eth0"),
    :direction(DIR_INBOUND)
);

is $pkt.packet-id, 101, "Packet ID matches";
is $pkt.wire-length, 64, "Wire length matches raw frame length";
nok $pkt.is-truncated, "Full frame is not truncated";

# Truncated packet test
my $pkt_trunc = Sigil::Core::Packet.new(
    :raw(Buf.new(1..32)),
    :packet-id(102),
    :wire-length(1500),
    :capture-length(32)
);
ok $pkt_trunc.is-truncated, "Truncation detected when capture length < wire length";

# Create protocol layers
my $eth_fl = Sigil::Core::FieldList.new;
$eth_fl.add(Sigil::Core::AddressField.new(
    :name("Source MAC"),
    :key("eth.src"),
    :value("00:11:22:33:44:55"),
    :address-type("mac")
));
my $eth_layer = Sigil::Core::Layer.new(:name("Ethernet"), :fields($eth_fl), :header-length(14));

my $ip_fl = Sigil::Core::FieldList.new;
$ip_fl.add(Sigil::Core::AddressField.new(
    :name("Source IP"),
    :key("ip.src"),
    :value("192.168.1.50"),
    :address-type("ipv4")
));
$ip_fl.add(Sigil::Core::AddressField.new(
    :name("Destination IP"),
    :key("ip.dst"),
    :value("10.0.0.1"),
    :address-type("ipv4")
));
my $ip_layer = Sigil::Core::Layer.new(:name("IPv4"), :fields($ip_fl), :header-length(20));

my $tcp_fl = Sigil::Core::FieldList.new;
$tcp_fl.add(Sigil::Core::IntField.new(
    :name("Source Port"),
    :key("tcp.srcport"),
    :value(54321)
));
$tcp_fl.add(Sigil::Core::IntField.new(
    :name("Destination Port"),
    :key("tcp.dstport"),
    :value(443)
));
my $tcp_layer = Sigil::Core::Layer.new(:name("TCP"), :fields($tcp_fl), :header-length(20));

# Push layers
$pkt.push-layer($eth_layer);
$pkt.push-layer($ip_layer);
$pkt.push-layer($tcp_layer);

is $pkt.layer-count, 3, "All three layers registered in packet stack";
ok $pkt.has-layer("Ethernet"), "Packet contains Ethernet layer";
ok $pkt.has-layer("IPv4"), "Packet contains IPv4 layer";
ok $pkt.has-layer("tcp"), "Case-insensitive layer lookup succeeds for TCP";
nok $pkt.has-layer("UDP"), "Nonexistent layer returns False";

# Highest and lowest layers
is $pkt.link-layer.name, "Ethernet", "Link layer is Ethernet";
is $pkt.highest-layer.name, "TCP", "Highest layer is TCP";

# Deep field lookup across entire stack
is $pkt.val("eth.src"), "00:11:22:33:44:55", "Deep lookup finds L2 field";
is $pkt.val("ip.dst"), "10.0.0.1", "Deep lookup finds L3 field";
is $pkt.val("tcp.dstport"), 443, "Deep lookup finds L4 field";

# Annotations
$pkt.annotate("threat-intel", "Suspicious beacon detected");
is $pkt.annotations<threat-intel>, "Suspicious beacon detected", "Annotations preserved on packet";
