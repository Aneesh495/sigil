# Test suite for Sigil::Grammar::Protocol::ICMPv4 and ICMPv6
use Test;
use Sigil::Grammar::Protocol::ICMPv4;
use Sigil::Grammar::Protocol::ICMPv6;
use Sigil::Types;

plan 14;

# ICMPv4 Echo Request (ping): Type 8, Code 0, Checksum, Ident=0x1234, Seq=1
my $icmp4_req = Buf.new(
    0x08, 0x00,                         # Type 8, Code 0
    0x00, 0x00,                         # Checksum zeroed for calculation
    0x12, 0x34,                         # Ident = 0x1234
    0x00, 0x01,                         # Seq = 1
    0x61, 0x62, 0x63, 0x64              # Payload "abcd"
);
my $ck4 = Sigil::Core::Checksum::internet-checksum($icmp4_req);
$icmp4_req[2] = $ck4 +> 8;
$icmp4_req[3] = $ck4 +& 0xFF;

my $layer4 = Sigil::Grammar::Protocol::ICMPv4.dissect($icmp4_req);
is $layer4.name, "ICMPv4", "ICMPv4 layer identified";
is $layer4.status, STATUS_OK, "ICMPv4 status OK with valid checksum";
is $layer4.val("icmp.type"), 8, "Type is 8 (Echo Request)";
is $layer4.val("icmp.code"), 0, "Code is 0";
is $layer4.val("icmp.ident"), 0x1234, "Identifier is 0x1234";
is $layer4.val("icmp.seq"), 1, "Sequence number is 1";
is $layer4.payload-length, 4, "Payload length is 4 bytes";

# ICMPv4 Destination Unreachable (Code 4: Fragmentation Needed, Next MTU = 1420)
my $icmp4_unreach = Buf.new(
    0x03, 0x04,                         # Type 3, Code 4
    0x00, 0x00,                         # Checksum zeroed
    0x00, 0x00,                         # Unused
    0x05, 0x8c                          # Next-Hop MTU = 1420 (0x058C)
);
my $ck4_unr = Sigil::Core::Checksum::internet-checksum($icmp4_unreach);
$icmp4_unreach[2] = $ck4_unr +> 8;
$icmp4_unreach[3] = $ck4_unr +& 0xFF;

my $layer4_unr = Sigil::Grammar::Protocol::ICMPv4.dissect($icmp4_unreach);
is $layer4_unr.val("icmp.next_mtu"), 1420, "Next-Hop MTU 1420 extracted for Path MTU discovery";

# ICMPv6 Echo Reply: Type 129, Code 0, Ident 0x5678, Seq 42
my $icmp6_reply = Buf.new(
    129, 0,                             # Type 129, Code 0
    0x00, 0x00,                         # Checksum
    0x56, 0x78,                         # Ident = 0x5678
    0x00, 0x2a                          # Seq = 42
);
my $layer6 = Sigil::Grammar::Protocol::ICMPv6.dissect($icmp6_reply);
is $layer6.name, "ICMPv6", "ICMPv6 layer identified";
is $layer6.val("icmpv6.type"), 129, "ICMPv6 type is 129 (Echo Reply)";
is $layer6.val("icmpv6.ident"), 0x5678, "Identifier is 0x5678";
is $layer6.val("icmpv6.seq"), 42, "Sequence number is 42";

# ICMPv6 Neighbor Solicitation (Type 135) with target address
my $icmp6_ns = Buf.new(
    135, 0,                             # Type 135, Code 0
    0x00, 0x00,                         # Checksum
    0x00, 0x00, 0x00, 0x00,             # Reserved
    # Target address fe80::1
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
);
my $layer6_ns = Sigil::Grammar::Protocol::ICMPv6.dissect($icmp6_ns);
is $layer6_ns.val("icmpv6.ndp.target"), "fe80:0:0:0:0:0:0:1", "NDP target IPv6 address decoded";

# Truncated ICMP
my $trunc = Buf.new(0x08, 0x00);
my $l_trunc = Sigil::Grammar::Protocol::ICMPv4.dissect($trunc);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated ICMP yields STATUS_TRUNCATED";
