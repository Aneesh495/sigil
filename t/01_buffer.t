# Test suite for Sigil::Core::Buffer
use Test;
use Sigil::Core::Buffer;
use Sigil::Core::Error;

plan 29;

# Basic creation and capacity
my $buf1 = Sigil::Core::Buffer.new([0x01, 0x02, 0x03, 0x04]);
is $buf1.size, 4, 'Buffer size initialized correctly';
is $buf1.remaining, 4, 'Initial remaining bytes equals capacity';
nok $buf1.at-eof, 'Not at EOF initially';

# Unsigned and signed 8-bit integers
is $buf1.read-uint8, 0x01, 'Read uint8 returns expected byte';
is $buf1.offset, 1, 'Offset incremented by 1';

my $buf_signed = Sigil::Core::Buffer.new([0x80, 0x7F, 0xFF]);
is $buf_signed.read-int8, -128, 'Read int8 handles minimum negative value';
is $buf_signed.read-int8, 127, 'Read int8 handles positive value';
is $buf_signed.read-int8, -1, 'Read int8 handles -1 representation';

# Endianness tests (16-bit and 32-bit)
my $buf_endian = Sigil::Core::Buffer.new([0x12, 0x34, 0x56, 0x78]);
is $buf_endian.read-uint16-be, 0x1234, 'Big-endian uint16 matches network byte order';
$buf_endian.seek(0);
is $buf_endian.read-uint16-le, 0x3412, 'Little-endian uint16 matches swapped byte order';

$buf_endian.seek(0);
is $buf_endian.read-uint32-be, 0x12345678, 'Big-endian uint32 matches full word';
$buf_endian.seek(0);
is $buf_endian.read-uint32-le, 0x78563412, 'Little-endian uint32 matches reversed order';

# 24-bit integer
my $buf_24 = Sigil::Core::Buffer.new([0x01, 0x02, 0x03]);
is $buf_24.read-uint24-be, 0x010203, 'Big-endian uint24 read accurately';

# 64-bit integer
my $buf_64 = Sigil::Core::Buffer.new([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);
is $buf_64.read-uint64-be, 0x100000002, 'Big-endian uint64 reconstructed without truncation';

# Sub-byte bitfield reads (IPv4 header style: version 4 bits, IHL 4 bits)
my $buf_bits = Sigil::Core::Buffer.new([0x45, 0x00]);
is $buf_bits.read-bits(4), 4, 'Bitfield read 4 bits: IP version 4';
is $buf_bits.read-bits(4), 5, 'Bitfield read 4 bits: IP header length 5 (20 bytes)';

# IPv4 Flags and Fragment Offset: 3 bits flags + 13 bits fragment offset
my $buf_frag = Sigil::Core::Buffer.new([0x40, 0x00]); # Don't Fragment bit set
is $buf_frag.read-bits(3), 2, 'Flags read: DF bit set (value 2)';
is $buf_frag.read-bits(13), 0, 'Fragment offset: 0';

# Address formatting
my $buf_addr = Sigil::Core::Buffer.new([
    0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, # MAC
    192, 168, 1, 100                     # IPv4
]);
is $buf_addr.read-mac, '00:1a:2b:3c:4d:5e', 'MAC address formatted as colon hex';
is $buf_addr.read-ipv4, '192.168.1.100', 'IPv4 formatted as dotted-decimal';

# IPv6 address formatting
my $buf_v6 = Sigil::Core::Buffer.new([
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
]);
is $buf_v6.read-ipv6, '2001:db8:0:0:0:0:0:1', 'IPv6 address parsed into canonical hex groups';

# String reading
my $buf_str = Sigil::Core::Buffer.new("SIGIL\0EXTRA".encode('ascii'));
is $buf_str.read-cstring, 'SIGIL', 'Read null-terminated C string terminates at null byte';
is $buf_str.read-ascii(5), 'EXTRA', 'Read fixed-length ASCII string';

# Checkpoint and rollback
my $buf_cp = Sigil::Core::Buffer.new([10, 20, 30, 40]);
$buf_cp.read-uint8; # offset = 1
$buf_cp.checkpoint;
$buf_cp.read-uint16-be; # offset = 3
is $buf_cp.offset, 3, 'Offset advanced past checkpoint';
$buf_cp.rollback;
is $buf_cp.offset, 1, 'Rollback reverted offset to saved checkpoint position';
is $buf_cp.read-uint8, 20, 'Next read retrieves byte following checkpoint';

# Bounds checking exception
my $buf_short = Sigil::Core::Buffer.new([1, 2]);
dies-ok { $buf_short.read-uint32-be }, 'Reading 4 bytes from 2-byte buffer throws exception';

# Hex dump output contains offset and ASCII column
my $dump = $buf_addr.hex-dump;
ok $dump.contains('00000000'), 'Hex dump contains zero offset marker';
ok $dump.contains('|'), 'Hex dump contains ASCII boundary delimiters';
