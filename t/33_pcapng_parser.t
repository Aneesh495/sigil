use v6.d;
use Test;
use Sigil::Types;
use Sigil::PCAP::Header;
use Sigil::PCAP::PCAPNG;

plan 10;

# Helper to build a little-endian 32-bit int as 4 bytes
sub le32(Int $val) {
    return (
        $val +& 0xFF,
        ($val +> 8) +& 0xFF,
        ($val +> 16) +& 0xFF,
        ($val +> 24) +& 0xFF
    ).Slip;
}

# Helper to build a little-endian 16-bit int as 2 bytes
sub le16(Int $val) {
    return (
        $val +& 0xFF,
        ($val +> 8) +& 0xFF
    ).Slip;
}

# 1. Construct binary PCAPNG stream
my @bytes;

# Block 1: Section Header Block (SHB) - 28 bytes
# Type: 0x0A0D0D0A (SHB)
@bytes.append(0x0A, 0x0D, 0x0D, 0x0A);
# Total Length: 28
@bytes.append(le32(28));
# Byte-Order Magic: 0x1A2B3C4D (little-endian byte order: 0x4D, 0x3C, 0x2B, 0x1A)
@bytes.append(0x4D, 0x3C, 0x2B, 0x1A);
# Major: 1, Minor: 0
@bytes.append(le16(1));
@bytes.append(le16(0));
# Section Length: -1 (unspecified 64-bit int)
@bytes.append(le32(0xFFFFFFFF), le32(0xFFFFFFFF));
# Trailing Total Length: 28
@bytes.append(le32(28));

# Block 2: Interface Description Block (IDB) - 20 bytes
# Type: 0x00000001 (IDB)
@bytes.append(le32(1));
# Total Length: 20
@bytes.append(le32(20));
# LinkType: 1 (Ethernet), Reserved: 0
@bytes.append(le16(1));
@bytes.append(le16(0));
# SnapLen: 65535
@bytes.append(le32(65535));
# Trailing Total Length: 20
@bytes.append(le32(20));

# Block 3: Enhanced Packet Block (EPB)
# Packet data: 14 bytes ("PCAPNG_TEST_01") -> 2 bytes padding to 4-byte boundary = 16 bytes
# Total Length = 12 (type + len + trailing_len) + 20 (if_id + ts_hi + ts_lo + cap_len + orig_len) + 16 (data+pad) = 48 bytes
my $pkt-payload = "PCAPNG_TEST_01".encode('ascii');
my $cap-len = $pkt-payload.elems; # 14
my $pad-len = (4 - ($cap-len % 4)) % 4; # 2
my $epb-len = 12 + 20 + $cap-len + $pad-len; # 48

# Type: 0x00000006 (EPB)
@bytes.append(le32(6));
# Total Length: 48
@bytes.append(le32($epb-len));
# Interface ID: 0
@bytes.append(le32(0));
# Timestamp High: 0, Low: 1500000 (1.5 seconds)
@bytes.append(le32(0));
@bytes.append(le32(1500000));
# Captured Length: 14, Original Length: 14
@bytes.append(le32($cap-len));
@bytes.append(le32($cap-len));
# Packet Data
@bytes.append($pkt-payload.list);
# Padding
@bytes.append(0 xx $pad-len);
# Trailing Total Length: 48
@bytes.append(le32($epb-len));

my $pcapng-buf = Buf.new(@bytes);
ok $pcapng-buf.elems >= 28 + 20 + 48, "Constructed valid multi-block PCAPNG byte stream";

# 2. Parse using Sigil::PCAP::PCAPNG
my $parser = Sigil::PCAP::PCAPNG.from-buffer($pcapng-buf);
my $pkt = $parser.read-next-packet();

ok $pkt.defined, "Parsed Enhanced Packet Block from PCAPNG stream";
is $pkt.packet-id, 1, "Packet ID is 1";
is $pkt.capture-length, 14, "Capture length is 14 bytes";
is $pkt.wire-length, 14, "Wire length is 14 bytes";
is-approx $pkt.timestamp, 1.5e0, 1e-4, "Packet timestamp computed from 64-bit microsecond counter";
is $pkt.interface, "iface0", "Interface mapped to iface0 from IDB";
is $pkt.raw.decode('ascii'), "PCAPNG_TEST_01", "Packet raw payload decoded accurately without trailing padding";

# Trailing read reaches EOF
my $eof = $parser.read-next-packet();
nok $eof.defined, "Reader reaches EOF after single EPB block";
is $parser.packet-count, 1, "Total packet count recorded as 1";

done-testing;
