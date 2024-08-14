# Test suite for Sigil::Filter::AST
use Test;
use Sigil::Filter::AST;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;

plan 10;

# Build mock packet with L2, L3, L4, L7 layers
my $fl_ip = Sigil::Core::FieldList.new;
$fl_ip.add(Sigil::Core::AddressField.new(:name("Source IP"), :key("ip.src"), :value("192.168.1.100"), :address-type("ipv4")));
$fl_ip.add(Sigil::Core::AddressField.new(:name("Destination IP"), :key("ip.dst"), :value("10.0.0.1"), :address-type("ipv4")));
$fl_ip.add(Sigil::Core::IntField.new(:name("TTL"), :key("ip.ttl"), :value(64)));
my $layer_ip = Sigil::Core::Layer.new(:name("IPv4"), :fields($fl_ip));

my $fl_tcp = Sigil::Core::FieldList.new;
$fl_tcp.add(Sigil::Core::IntField.new(:name("Dest Port"), :key("tcp.dstport"), :value(443)));
$fl_tcp.add(Sigil::Core::IntField.new(:name("Source Port"), :key("tcp.srcport"), :value(51234)));
my $layer_tcp = Sigil::Core::Layer.new(:name("TCP"), :fields($fl_tcp));

my $fl_http = Sigil::Core::FieldList.new;
$fl_http.add(Sigil::Core::StringField.new(:name("Host"), :key("http.host"), :value("api.github.com")));
my $layer_http = Sigil::Core::Layer.new(:name("HTTP"), :fields($fl_http));

my $pkt = Sigil::Core::Packet.new(:raw(Buf.new(1..64)));
$pkt.push-layer($layer_ip);
$pkt.push-layer($layer_tcp);
$pkt.push-layer($layer_http);

# 1. ProtoNode
my $p_tcp = Sigil::Filter::AST::ProtoNode.new(:proto-name("tcp"));
ok $p_tcp.evaluate($pkt), "ProtoNode matches present layer TCP";
my $p_udp = Sigil::Filter::AST::ProtoNode.new(:proto-name("udp"));
nok $p_udp.evaluate($pkt), "ProtoNode rejects absent layer UDP";

# 2. CompareNode
my $cmp_port = Sigil::Filter::AST::CompareNode.new(:field-key("tcp.dstport"), :op("=="), :target-val(443));
ok $cmp_port.evaluate($pkt), "CompareNode matches tcp.dstport == 443";
my $cmp_port_bad = Sigil::Filter::AST::CompareNode.new(:field-key("tcp.dstport"), :op("=="), :target-val(80));
nok $cmp_port_bad.evaluate($pkt), "CompareNode rejects tcp.dstport == 80";

# 3. StringContainsNode
my $contains_node = Sigil::Filter::AST::StringContainsNode.new(:field-key("http.host"), :substring("github"));
ok $contains_node.evaluate($pkt), "StringContainsNode matches 'github' in host";

# 4. SetInNode
my $set_node = Sigil::Filter::AST::SetInNode.new(:field-key("tcp.dstport"), :set-values([80, 443, 8080]));
ok $set_node.evaluate($pkt), "SetInNode matches 443 in set";

# 5. CIDRNode
my $cidr_match = Sigil::Filter::AST::CIDRNode.new(:field-key("ip.src"), :cidr("192.168.0.0/16"));
ok $cidr_match.evaluate($pkt), "CIDRNode matches 192.168.1.100 in 192.168.0.0/16";
my $cidr_nomatch = Sigil::Filter::AST::CIDRNode.new(:field-key("ip.src"), :cidr("10.0.0.0/8"));
nok $cidr_nomatch.evaluate($pkt), "CIDRNode rejects 192.168.1.100 in 10.0.0.0/8";

# 6. Boolean AND / OR / NOT
my $and_node = Sigil::Filter::AST::AndNode.new(:left($p_tcp), :right($cmp_port));
ok $and_node.evaluate($pkt), "AndNode evaluates True for True AND True";

my $not_node = Sigil::Filter::AST::NotNode.new(:child($p_udp));
ok $not_node.evaluate($pkt), "NotNode inverts False to True";
