# Test suite for Sigil::Grammar::Protocol::WebSocket
use Test;
use Sigil::Grammar::Protocol::WebSocket;
use Sigil::Types;

plan 11;

# Client Masked Text Frame sending "Hello" (RFC 6455 Section 5.7 example)
# Byte 0: 0x81 (FIN=1, Opcode=1 Text)
# Byte 1: 0x85 (Mask=1, Length=5)
# Masking key: 0x37 0xfa 0x21 0x3d
# Payload: "Hello" XOR mask
# 'H'(0x48) ^ 0x37 = 0x7f
# 'e'(0x65) ^ 0xfa = 0x9f
# 'l'(0x6c) ^ 0x21 = 0x4d
# 'l'(0x6c) ^ 0x3d = 0x51
# 'o'(0x6f) ^ 0x37 = 0x58
my $ws_masked = Buf.new(
    0x81, 0x85,                         # FIN=1, Text, Mask=1, Len=5
    0x37, 0xfa, 0x21, 0x3d,             # Masking key
    0x7f, 0x9f, 0x4d, 0x51, 0x58        # Masked "Hello"
);

my $layer = Sigil::Grammar::Protocol::WebSocket.dissect($ws_masked);
is $layer.name, "WebSocket", "Layer identified as WebSocket";
is $layer.status, STATUS_OK, "Status is OK";
is $layer.val("ws.fin"), True, "FIN bit is set";
is $layer.val("ws.opcode"), 1, "Opcode is 1 (Text Frame)";
is $layer.val("ws.mask"), True, "Masked bit is True";
is $layer.val("ws.length"), 5, "Payload length is 5";
is $layer.val("ws.payload_text"), "Hello", "Masked payload unmasked accurately as 'Hello'";

# Server Unmasked Ping Frame (Opcode 9, Len 4)
my $ws_ping = Buf.new(
    0x89, 0x04,                         # FIN=1, Opcode=9 (Ping), Mask=0, Len=4
    0x01, 0x02, 0x03, 0x04              # Data
);
my $l_ping = Sigil::Grammar::Protocol::WebSocket.dissect($ws_ping);
is $l_ping.val("ws.opcode"), 9, "Opcode is 9 (Ping)";
is $l_ping.val("ws.mask"), False, "Masked bit is False";

# Extended 16-bit payload length (len code 126)
my @big_bytes = (0x82, 126, 0x01, 0x00); # FIN=1, Binary, Len 256
for 1..256 { @big_bytes.push(0xaa); }
my $ws_big = Buf.new(@big_bytes);
my $l_big = Sigil::Grammar::Protocol::WebSocket.dissect($ws_big);
is $l_big.val("ws.length"), 256, "16-bit extended length decoded as 256";

# Truncated WebSocket frame (< 2 bytes)
my $trunc_raw = Buf.new(0x81);
my $l_trunc = Sigil::Grammar::Protocol::WebSocket.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated frame yields STATUS_TRUNCATED";
