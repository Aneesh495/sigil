# Test suite for Sigil::Grammar::Protocol::TCP
use Test;
use Sigil::Grammar::Protocol::TCP;
use Sigil::Types;

plan 16;

# Real TCP SYN segment with options (Header length = 32 bytes = Data offset 8):
# Ports: 54321 -> 443
# Seq = 1000000, Ack = 0
# Flags: SYN (0x0002)
# Window = 65535
# Options:
#   MSS (Kind 2, Len 4, Val 1460 = 0x05B4)
#   SACK Permitted (Kind 4, Len 2)
#   Timestamps (Kind 8, Len 10, TSval 12345, TSecr 0)
#   NOP (Kind 1), Window Scale (Kind 3, Len 3, Shift 7)
my $tcp_syn = Buf.new(
    0xd4, 0x31,                         # Src port 54321
    0x01, 0xbb,                         # Dst port 443 (HTTPS)
    0x00, 0x0f, 0x42, 0x40,             # Seq = 1,000,000
    0x00, 0x00, 0x00, 0x00,             # Ack = 0
    0x80, 0x02,                         # Data offset 8 (32 bytes), Flags = SYN
    0xff, 0xff,                         # Window = 65535
    0xab, 0xcd,                         # Checksum
    0x00, 0x00,                         # Urgent ptr
    # TCP Options (12 bytes)
    0x02, 0x04, 0x05, 0xb4,             # MSS = 1460
    0x04, 0x02,                         # SACK Permitted
    0x01,                               # NOP
    0x03, 0x03, 0x07,                   # Window Scale = 7
    0x00, 0x00                          # Padding to 32 bytes (EOOL)
);

my $layer = Sigil::Grammar::Protocol::TCP.dissect($tcp_syn);
is $layer.name, "TCP", "Layer identified as TCP";
is $layer.status, STATUS_OK, "Status is OK";
is $layer.header-length, 32, "Header length decoded as 32 bytes";
is $layer.val("tcp.srcport"), 54321, "Source port decoded";
is $layer.val("tcp.dstport"), 443, "Destination port decoded";
is $layer.val("tcp.seq"), 1000000, "Sequence number decoded";
is $layer.val("tcp.ack"), 0, "Ack number decoded";
is $layer.val("tcp.window_size"), 65535, "Window size decoded";
is $layer.val("tcp.flags.syn"), True, "SYN flag is set";
is $layer.val("tcp.flags.ack"), False, "ACK flag is unset";
is $layer.val("tcp.flags.fin"), False, "FIN flag is unset";

# Options decoding
is $layer.val("tcp.options.mss"), 1460, "TCP MSS option parsed as 1460";
is $layer.val("tcp.options.wscale"), 7, "Window scale shift parsed as 7";
is $layer.val("tcp.options.sack_perm"), True, "SACK permitted option parsed";

# Malformed data offset (< 5)
my $bad_offset = Buf.new(
    0x00, 0x50, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0,
    0x40, 0x00, 0, 0, 0, 0, 0, 0 # Offset = 4
);
my $bad_layer = Sigil::Grammar::Protocol::TCP.dissect($bad_offset);
is $bad_layer.status, STATUS_MALFORMED, "Data offset < 5 yields STATUS_MALFORMED";

# Truncated TCP header
my $trunc_raw = Buf.new(0x00, 0x50, 0x00);
my $trunc_layer = Sigil::Grammar::Protocol::TCP.dissect($trunc_raw);
is $trunc_layer.status, STATUS_TRUNCATED, "Truncated TCP header yields STATUS_TRUNCATED";
