# Test suite for Sigil::Core::Registry
use Test;
use Sigil::Core::Registry;

plan 10;

my $reg = Sigil::Core::Registry.instance;
ok $reg.defined, "Registry singleton instantiated";
is Sigil::Core::Registry.instance.WHICH, $reg.WHICH, "Registry returns identical singleton instance";

# Mock dissector identifiers
my $mock_eth = "Mock::Ethernet";
my $mock_ip4 = "Mock::IPv4";
my $mock_tcp = "Mock::TCP";
my $mock_http = "Mock::HTTP";
my $mock_dns = "Mock::DNS";

# Linktype routing
$reg.register-linktype(1, $mock_eth);
is $reg.find-by-linktype(1), $mock_eth, "Find dissector by linktype DLT_EN10MB = 1";
nok $reg.find-by-linktype(999).defined, "Unregistered linktype returns undefined";

# EtherType routing
$reg.register-ethertype(0x0800, $mock_ip4);
is $reg.find-by-ethertype(0x0800), $mock_ip4, "Find dissector by EtherType 0x0800";

# IP protocol routing
$reg.register-ipproto(6, $mock_tcp);
is $reg.find-by-ipproto(6), $mock_tcp, "Find dissector by IP proto 6 (TCP)";

# TCP and UDP port routing
$reg.register-tcp-port(80, $mock_http);
$reg.register-udp-port(53, $mock_dns);
is $reg.find-by-tcp-port(80), $mock_http, "Find dissector by TCP port 80";
is $reg.find-by-udp-port(53), $mock_dns, "Find dissector by UDP port 53";

# Heuristic routing
$reg.register-heuristic(sub (Buf $p, Str $transport --> Bool) {
    return $transport eq 'TCP' && $p.elems >= 4 && $p[0] == 0x47 && $p[1] == 0x45 && $p[2] == 0x54 && $p[3] == 0x20; # 'GET '
}, $mock_http);

my $get_buf = Buf.new("GET / HTTP/1.1\r\n".encode('ascii'));
my $other_buf = Buf.new([0x00, 0x01, 0x02]);

is $reg.find-by-heuristic($get_buf, 'TCP'), $mock_http, "Heuristic probe identifies HTTP GET request";
nok $reg.find-by-heuristic($other_buf, 'TCP').defined, "Heuristic probe rejects non-matching payload";
