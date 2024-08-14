# Test suite for Sigil::Filter::Compiler and Sigil::Filter::Engine
use Test;
use Sigil::Filter::Compiler;
use Sigil::Filter::Engine;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Core::Error;

plan 11;

my $compiler = Sigil::Filter::Compiler.new;
my $engine = Sigil::Filter::Engine.new(:$compiler);

# Build sample packet
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

# 1. Simple protocol predicate
$engine.set-filter("tcp");
ok $engine.matches($pkt), "Filter 'tcp' matches TCP packet";

$engine.set-filter("udp");
nok $engine.matches($pkt), "Filter 'udp' rejects TCP packet";

# 2. Relational equality comparison
$engine.set-filter("tcp.dstport == 443");
ok $engine.matches($pkt), "Filter 'tcp.dstport == 443' matches";

$engine.set-filter("tcp.dstport == 80");
nok $engine.matches($pkt), "Filter 'tcp.dstport == 80' rejects";

# 3. CIDR matching
$engine.set-filter("ip.src in 192.168.0.0/16");
ok $engine.matches($pkt), "Filter 'ip.src in 192.168.0.0/16' matches";

# 4. Set membership
$engine.set-filter("tcp.dstport in [80, 443, 8080]");
ok $engine.matches($pkt), "Filter 'tcp.dstport in [80, 443, 8080]' matches";

# 5. String contains
$engine.set-filter('http.host contains "github"');
ok $engine.matches($pkt), "Filter 'http.host contains \"github\"' matches";

# 6. Compound boolean expression
$engine.set-filter("tcp and ip.src in 192.168.0.0/16 and tcp.dstport == 443");
ok $engine.matches($pkt), "Compound AND filter matches";

# 7. Parenthesized OR / AND precedence
$engine.set-filter("(tcp and tcp.dstport == 443) or (udp and udp.dstport == 53)");
ok $engine.matches($pkt), "Parenthesized compound expression matches";

# 8. Negation
$engine.set-filter("not udp");
ok $engine.matches($pkt), "Filter 'not udp' matches non-UDP packet";

# 9. Invalid syntax error throwing
throws-like {
    $compiler.compile("tcp and == 443");
}, X::Sigil::FilterSyntaxError, "Invalid filter syntax throws X::Sigil::FilterSyntaxError";
