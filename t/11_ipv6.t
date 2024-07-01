# Test suite for Sigil::Grammar::Protocol::IPv6
use Test;
use Sigil::Grammar::Protocol::IPv6;
use Sigil::Types;

plan 11;

# Standard 40-byte IPv6 packet:
# Version 6, Traffic class 0, Flow label 0x12345
# Payload length = 20, Next header = 6 (TCP), Hop limit = 64
# Src: 2001:db8::1, Dst: 2001:db8::2
my $ipv6_raw = Buf.new(
    0x60, 0x01, 0x23, 0x45,             # Ver=6, TC=0, Flow=0x12345
    0x00, 0x14,                         # Payload length 20
    0x06,                               # Next header = TCP (6)
    0x40,                               # Hop limit = 64
    # Src IP: 2001:0db8:0000:0000:0000:0000:0000:0001
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    # Dst IP: 2001:0db8:0000:0000:0000:0000:0000:0002
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    # 20 bytes payload
    1..20
);

my $layer = Sigil::Grammar::Protocol::IPv6.dissect($ipv6_raw);
is $layer.name, "IPv6", "Layer identified as IPv6";
is $layer.status, STATUS_OK, "Status is OK";
is $layer.header-length, 40, "Header length 40 bytes";
is $layer.val("ipv6.version"), 6, "Version is 6";
is $layer.val("ipv6.flow"), 0x12345, "Flow label decoded as 0x12345";
is $layer.val("ipv6.plen"), 20, "Payload length is 20";
is $layer.val("ipv6.hlim"), 64, "Hop limit is 64";
is $layer.val("ipv6.src"), "2001:db8:0:0:0:0:0:1", "Source IPv6 decoded";
is $layer.val("ipv6.dst"), "2001:db8:0:0:0:0:0:2", "Dest IPv6 decoded";
is $layer.next-protocol, 6, "Next protocol is 6 (TCP)";

# Truncated IPv6 packet (< 40 bytes)
my $trunc = Buf.new(0x60, 0x00, 0x00, 0x00);
my $l_trunc = Sigil::Grammar::Protocol::IPv6.dissect($trunc);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated IPv6 header yields STATUS_TRUNCATED";
