# Test suite for Sigil::Grammar::Protocol::IPv4
use Test;
use Sigil::Grammar::Protocol::IPv4;
use Sigil::Types;

plan 14;

# Real standard IPv4 packet header: 20 bytes
# 45 00 00 3c 1c 46 40 00 40 06 b1 e6 ac 10 0a 63 ac 10 0a 0c
my $ipv4_raw = Buf.new(
    0x45, 0x00,                         # Version 4, IHL 5 (20 bytes), DSCP/ECN 0
    0x00, 0x28,                         # Total Length 40 bytes (20 hdr + 20 payload)
    0x1c, 0x46,                         # ID 0x1c46
    0x40, 0x00,                         # Flags: DF set, Frag offset: 0
    0x40, 0x06,                         # TTL 64, Protocol 6 (TCP)
    0xb1, 0xfa,                         # Checksum recalculated for 0x0028 total len
    172, 16, 10, 99,                    # Source IP: 172.16.10.99
    172, 16, 10, 12,                    # Dest IP: 172.16.10.12
    # 20 bytes payload
    1..20
);

# Recalculate checksum so it is mathematically valid
my $hdr_part = $ipv4_raw.subbuf(0, 20);
$hdr_part[10] = 0; $hdr_part[11] = 0;
my $ck = Sigil::Core::Checksum::internet-checksum($hdr_part);
$ipv4_raw[10] = $ck +> 8;
$ipv4_raw[11] = $ck +& 0xFF;

my $layer = Sigil::Grammar::Protocol::IPv4.dissect($ipv4_raw);
is $layer.name, "IPv4", "Layer identified as IPv4";
is $layer.status, STATUS_OK, "Status is OK with valid checksum";
is $layer.header-length, 20, "Header length is 20 bytes";
is $layer.val("ip.version"), 4, "Version is 4";
is $layer.val("ip.src"), "172.16.10.99", "Source IP decoded";
is $layer.val("ip.dst"), "172.16.10.12", "Dest IP decoded";
is $layer.val("ip.ttl"), 64, "TTL decoded as 64";
is $layer.val("ip.proto"), 6, "Next protocol is 6 (TCP)";
is $layer.val("ip.flags.df"), True, "DF bit is set";
is $layer.val("ip.flags.mf"), False, "MF bit is unset";
is $layer.val("ip.frag_offset"), 0, "Fragment offset is 0";
is $layer.payload-length, 20, "Payload length matches expected remaining bytes";

# Corrupt checksum detection
my $corrupt_raw = $ipv4_raw.subbuf(0);
$corrupt_raw[10] = ($corrupt_raw[10] +^ 0xFF) +& 0xFF; # Invert checksum byte
my $corrupt_layer = Sigil::Grammar::Protocol::IPv4.dissect($corrupt_raw);
is $corrupt_layer.status, STATUS_CHECKSUM_MISMATCH, "Corrupt checksum detected as STATUS_CHECKSUM_MISMATCH";

# Truncated IPv4 header (< 20 bytes)
my $trunc_raw = Buf.new(0x45, 0x00, 0x00, 0x14);
my $trunc_layer = Sigil::Grammar::Protocol::IPv4.dissect($trunc_raw);
is $trunc_layer.status, STATUS_TRUNCATED, "Truncated IPv4 header yields STATUS_TRUNCATED";
