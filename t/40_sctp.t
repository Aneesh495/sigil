use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Layer;
use Sigil::Grammar::Protocol::SCTP;

plan 9;

my $dissector = Sigil::Grammar::Protocol::SCTP.new;

# Construct synthetic SCTP datagram with Common Header + DATA Chunk
my @bytes = (
    # Common Header (12 bytes)
    0x0B, 0x90,             # Source Port = 2960
    0x0B, 0x90,             # Destination Port = 2960
    0x12, 0x34, 0x56, 0x78, # Verification Tag = 0x12345678
    0xDE, 0xAD, 0xBE, 0xEF, # Checksum = 0xDEADBEEF

    # Chunk 1: DATA Chunk (Type=0, Flags=0x03 [E+B fragments complete], Len=21)
    # Len = 4 (chunk header) + 12 (data header) + 5 (payload 'HELLO') = 21 bytes
    # Padding: (4 - (21 % 4)) = 3 bytes -> total on wire = 24 bytes
    0x00,                   # Type = DATA (0)
    0x03,                   # Flags (Beginning + Ending)
    0x00, 0x15,             # Length = 21
    0x00, 0x00, 0x00, 0x01, # TSN = 1
    0x00, 0x02,             # Stream ID = 2
    0x00, 0x05,             # Stream Sequence = 5
    0x00, 0x00, 0x00, 0x03, # PPID = 3
    0x48, 0x45, 0x4C, 0x4C, 0x4F, # "HELLO" (5 bytes)
    0x00, 0x00, 0x00        # 3 bytes padding
);

my $raw = Buf.new(@bytes);
my $layer = $dissector.dissect($raw);

ok $layer.defined, "SCTP layer dissected successfully";
is $layer.status, STATUS_OK, "Dissection status is STATUS_OK";
is $layer.val("sctp.srcport"), 2960, "Source Port is 2960";
is $layer.val("sctp.dstport"), 2960, "Destination Port is 2960";
is $layer.val("sctp.vtag"), 0x12345678, "Verification Tag is 0x12345678";
is $layer.val("sctp.data.tsn"), 1, "DATA chunk TSN is 1";
is $layer.val("sctp.data.sid"), 2, "Stream ID is 2";
is $layer.val("sctp.data.ssn"), 5, "Stream Sequence Number is 5";
is $layer.val("sctp.chunk_count"), 1, "Chunk count is 1";

done-testing;
