# Test suite for Sigil::Grammar::Protocol::UDP
use Test;
use Sigil::Grammar::Protocol::UDP;
use Sigil::Types;

plan 10;

# Standard DNS query over UDP: Src port 51234, Dst port 53, Length 16 (8 hdr + 8 payload)
my $udp_raw = Buf.new(
    0xc8, 0x22,                         # Src Port 51234
    0x00, 0x35,                         # Dst Port 53 (DNS)
    0x00, 0x10,                         # Length 16 bytes
    0x1a, 0x2b,                         # Checksum 0x1a2b
    # 8 bytes payload
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
);

my $layer = Sigil::Grammar::Protocol::UDP.dissect($udp_raw);
is $layer.name, "UDP", "Layer identified as UDP";
is $layer.status, STATUS_OK, "Status OK";
is $layer.header-length, 8, "Header length 8 bytes";
is $layer.val("udp.srcport"), 51234, "Source port decoded";
is $layer.val("udp.dstport"), 53, "Destination port decoded";
is $layer.val("udp.length"), 16, "Datagram length decoded";
is $layer.payload-length, 8, "Payload length is 8 bytes";
is $layer.next-protocol, 53, "Next protocol routed to port 53 (DNS)";

# Malformed length (< 8 bytes)
my $bad_len_raw = Buf.new(0x00, 0x50, 0x00, 0x50, 0x00, 0x04, 0x00, 0x00);
my $bad_layer = Sigil::Grammar::Protocol::UDP.dissect($bad_len_raw);
is $bad_layer.status, STATUS_MALFORMED, "Length < 8 yields STATUS_MALFORMED";

# Truncated UDP header
my $trunc_raw = Buf.new(0x00, 0x50, 0x00);
my $trunc_layer = Sigil::Grammar::Protocol::UDP.dissect($trunc_raw);
is $trunc_layer.status, STATUS_TRUNCATED, "Truncated header yields STATUS_TRUNCATED";
