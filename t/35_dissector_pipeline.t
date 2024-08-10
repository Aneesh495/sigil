# Test suite for Sigil::Core::Dissector recursive pipeline
use Test;
use Sigil::Core::Dissector;
use Sigil::Types;

plan 16;

my $engine = Sigil::Core::Dissector.new;
ok $engine.defined, "Dissector engine instantiated";

# 1. Full Ethernet -> IPv4 -> UDP -> DNS Query packet
# Ethernet: 14 bytes
my @pkt_dns;
# Eth Dst: 00:11:22:33:44:55, Src: 66:77:88:99:aa:bb, Type 0x0800 (IPv4)
@pkt_dns.push(0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00);

# IPv4: 20 bytes, Src 192.168.1.100, Dst 8.8.8.8, Proto UDP (17), Total Len 20 + 8 + 29 = 57 bytes
my @ip_bytes = (
    0x45, 0x00, 0x00, 0x39,
    0x12, 0x34, 0x40, 0x00,
    0x40, 0x11, 0x00, 0x00,
    192, 168, 1, 100,
    8, 8, 8, 8
);
my $ip_ck = Sigil::Core::Checksum::internet-checksum(Buf.new(@ip_bytes));
@ip_bytes[10] = $ip_ck +> 8;
@ip_bytes[11] = $ip_ck +& 0xFF;
for @ip_bytes { @pkt_dns.push($_); }

# UDP: 8 bytes, Src 53456, Dst 53, Len 37, Checksum 0
@pkt_dns.push(0xd0, 0xd0, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00);

# DNS Query for "sigil.internal" (Type A): 29 bytes
@pkt_dns.push(
    0xaa, 0xbb,                         # TxID
    0x01, 0x00,                         # Flags (RD=1)
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x73, 0x69, 0x67, 0x69, 0x6c, # "sigil"
    0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, # "internal"
    0x00,                               # End of name
    0x00, 0x01,                         # Type A
    0x00, 0x01                          # Class IN
);

my $dns_frame = Buf.new(@pkt_dns);

my $pkt = $engine.dissect-packet($dns_frame, :packet-id(1));
is $pkt.layer-count, 4, "Packet dissected through 4 protocol layers (Eth -> IP -> UDP -> DNS)";
ok $pkt.has-layer("Ethernet"), "Ethernet layer present";
ok $pkt.has-layer("IPv4"), "IPv4 layer present";
ok $pkt.has-layer("UDP"), "UDP layer present";
ok $pkt.has-layer("DNS"), "DNS layer present";

is $pkt.val("eth.dst"), "00:11:22:33:44:55", "L2 destination MAC decoded";
is $pkt.val("ip.src"), "192.168.1.100", "L3 source IP decoded";
is $pkt.val("ip.dst"), "8.8.8.8", "L3 destination IP decoded";
is $pkt.val("udp.dstport"), 53, "L4 destination port decoded as 53";
is $pkt.val("dns.id"), 0xaabb, "L7 DNS transaction ID decoded";
is $pkt.val("dns.qry.name"), "sigil.internal", "L7 DNS query name decoded";

# 2. Test ARP packet through pipeline
my @pkt_arp = (
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, # Eth ARP
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, # ARP HType 1, Proto 0x0800, Op Request
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 10, 0, 0, 1, # Sender
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 0, 0, 2  # Target
);
my $arp_pkt = $engine.dissect-packet(Buf.new(@pkt_arp), :packet-id(2));
is $arp_pkt.layer-count, 2, "ARP frame has 2 layers (Eth -> ARP)";
is $arp_pkt.highest-layer.name, "ARP", "Highest layer is ARP";

# Verify engine statistics
my %stats = $engine.stats;
is %stats<packets_processed>, 2, "Engine processed 2 packets";
ok %stats<protocols><DNS> >= 1, "DNS protocol counter recorded";
