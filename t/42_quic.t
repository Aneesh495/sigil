use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Layer;
use Sigil::Grammar::Protocol::QUIC;

plan 8;

my $dissector = Sigil::Grammar::Protocol::QUIC.new;

# Construct synthetic QUIC Initial Long Header Packet (RFC 9000)
# First Byte: 0xC0 (Long Header = 1, Fixed Bit = 1, Type = Initial 0x00)
# Version: 0x00000001 (QUIC v1)
# DCID: 8 bytes (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
# SCID: 4 bytes (0xAA, 0xBB, 0xCC, 0xDD)
my @bytes = (
    0xC0,                   # Long Header, Initial
    0x00, 0x00, 0x00, 0x01, # Version QUIC v1
    0x08,                   # DCID Length = 8
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x04,                   # SCID Length = 4
    0xAA, 0xBB, 0xCC, 0xDD,
    0x11, 0x22, 0x33, 0x44  # Protected payload bytes
);

my $raw = Buf.new(@bytes);
my $layer = $dissector.dissect($raw);

ok $layer.defined, "QUIC layer dissected successfully";
is $layer.status, STATUS_OK, "Dissection status is STATUS_OK";
ok $layer.val("quic.header_form"), "Header form is Long Header";
ok $layer.val("quic.fixed_bit"), "Fixed bit is set";
is $layer.val("quic.long.packet_type"), 0, "Packet type is Initial (0)";
is $layer.val("quic.version"), 0x00000001, "Version is QUIC v1";
is $layer.val("quic.dcid"), "0102030405060708", "DCID hex matches";
is $layer.val("quic.scid"), "aabbccdd", "SCID hex matches";

done-testing;
