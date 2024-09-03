use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Packet;
use Sigil::Core::Dissector;
use Sigil::Grammar::Protocol::Ethernet;
use Sigil::Grammar::Protocol::IPv4;
use Sigil::Grammar::Protocol::TCP;
use Sigil::Grammar::Protocol::UDP;
use Sigil::Grammar::Protocol::DNS;

plan 14;

my $pipeline = Sigil::Core::Dissector.new;

# 1. Zero-length buffer
{
    my $pkt = $pipeline.dissect-packet(Buf.new, :packet-id(1));
    ok $pkt.defined, "Dissecting zero-length buffer does not crash";
    is $pkt.layer-count, 0, "Zero layers extracted from empty buffer";
}

# 2. Truncated Ethernet header (7 bytes instead of 14)
{
    my $raw = Buf.new(1..7);
    my $pkt = $pipeline.dissect-packet($raw, :packet-id(2));
    ok $pkt.defined, "Truncated Ethernet frame handled gracefully";
    my $eth = $pkt.layer("Ethernet");
    ok $eth.defined, "Ethernet layer object instantiated";
    is $eth.status, STATUS_TRUNCATED, "Ethernet layer status flagged as STATUS_TRUNCATED";
}

# 3. Truncated IPv4 header (Ethernet ok, but only 10 bytes IPv4 instead of 20)
{
    my @b = (0 xx 12);
    @b.push(0x08, 0x00); # EtherType = IPv4
    @b.append(0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00); # Only 8 bytes of IPv4
    my $pkt = $pipeline.dissect-packet(Buf.new(@b), :packet-id(3));
    my $ip = $pkt.layer("IPv4");
    ok $ip.defined, "IPv4 layer created";
    is $ip.status, STATUS_TRUNCATED, "IPv4 flagged as STATUS_TRUNCATED";
}

# 4. Invalid IPv4 IHL (< 5)
{
    my @b = (0 xx 12);
    @b.push(0x08, 0x00); # IPv4
    @b.append(0x44, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00);
    @b.append(0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02);
    my $pkt = $pipeline.dissect-packet(Buf.new(@b), :packet-id(4));
    my $ip = $pkt.layer("IPv4");
    ok $ip.defined, "IPv4 layer created";
    is $ip.status, STATUS_MALFORMED, "IPv4 with IHL=4 flagged as STATUS_MALFORMED";
}

# 5. Truncated TCP header (IPv4 ok, but only 8 bytes of TCP)
{
    my @b = (0 xx 12);
    @b.push(0x08, 0x00); # IPv4
    # Valid 20-byte IPv4 header with proto=6 (TCP)
    @b.append(0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00);
    @b.append(0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02);
    # Only 8 bytes of TCP
    @b.append(0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01);
    my $pkt = $pipeline.dissect-packet(Buf.new(@b), :packet-id(5));
    my $tcp = $pkt.layer("TCP");
    ok $tcp.defined, "TCP layer created";
    is $tcp.status, STATUS_TRUNCATED, "Truncated TCP header flagged as STATUS_TRUNCATED";
}

# 6. DNS Pointer Loop Defense (0xC0 0x00 pointer pointing to itself)
{
    my @b = (0 xx 12);
    @b.push(0x08, 0x00); # IPv4
    # IPv4 header with proto=17 (UDP)
    @b.append(0x45, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00);
    @b.append(0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02);
    # UDP header
    @b.append(0x00, 0x35, 0x00, 0x35, 0x00, 0x0E, 0x00, 0x00);
    # DNS header with 1 query, but query name has recursive compression pointer 0xC0 0x0C (points to offset 12 in DNS)
    @b.append(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    @b.append(0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01); # Infinite pointer loop
    my $pkt = $pipeline.dissect-packet(Buf.new(@b), :packet-id(6));
    ok $pkt.defined, "DNS compression pointer loop does not enter infinite recursion or hang";
    my $dns = $pkt.layer("DNS");
    ok $dns.defined, "DNS layer instantiated without crash";
    is $dns.status, STATUS_MALFORMED, "Recursive pointer loop terminates defensively with STATUS_MALFORMED";
}

done-testing;
