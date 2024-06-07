# Test suite for Sigil::Core::Checksum
use Test;
use Sigil::Core::Checksum;

plan 11;

# Standard RFC 1071 calculation on IPv4 header sample
# Real IPv4 header: 45 00 00 3c 1c 46 40 00 40 06 [b1 e6] ac 10 0a 63 ac 10 0a 0c
# With checksum zeroed out: 45 00 00 3c 1c 46 40 00 40 06 00 00 ac 10 0a 63 ac 10 0a 0c
my $ip_header_zeroed = Buf.new(
    0x45, 0x00, 0x00, 0x3c,
    0x1c, 0x46, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00, # Checksum field = 0x0000
    0xac, 0x10, 0x0a, 0x63,
    0xac, 0x10, 0x0a, 0x0c
);

my $computed_ip_cksum = internet-checksum($ip_header_zeroed);
is $computed_ip_cksum, 0xb1e6, "Internet checksum computes valid IPv4 header checksum 0xb1e6";

# Complete IPv4 header with calculated checksum populated
my $ip_header_valid = Buf.new(
    0x45, 0x00, 0x00, 0x3c,
    0x1c, 0x46, 0x40, 0x00,
    0x40, 0x06, 0xb1, 0xe6, # Checksum field = 0xb1e6
    0xac, 0x10, 0x0a, 0x63,
    0xac, 0x10, 0x0a, 0x0c
);
ok verify-internet-checksum($ip_header_valid), "Checksum verification succeeds on valid packet header";

# Corrupt single byte in header
my $ip_header_corrupt = $ip_header_valid.subbuf(0);
$ip_header_corrupt[0] = 0x46; # Version/IHL corrupted
nok verify-internet-checksum($ip_header_corrupt), "Checksum verification detects single-byte bit flip";

# Odd-length buffer checksum calculation
my $odd_buf = Buf.new(0x01, 0x02, 0x03);
my $odd_cksum = internet-checksum($odd_buf);
ok $odd_cksum > 0, "Odd-length buffer padded and checksum computed without fault";

# IEEE 802.3 CRC-32 standard test vector: "123456789" -> 0xCBF43926
my $crc_input = Buf.new("123456789".encode('ascii'));
my $computed_crc = crc32($crc_input);
is sprintf("0x%08X", $computed_crc), "0xCBF43926", "CRC-32 matches ISO 3309 test vector 0xCBF43926";

# Empty buffer CRC-32 is 0
is crc32(Buf.new), 0, "Empty buffer CRC-32 returns 0";

# Adler-32 standard test vector: "123456789" -> 0x091E01DE
my $computed_adler = adler32($crc_input);
is sprintf("0x%08X", $computed_adler), "0x091E01DE", "Adler-32 matches RFC 1950 test vector 0x091E01DE";

# IPv4 pseudo-header checksum computation
my $pseudo_sum = ipv4-pseudo-header-sum("192.168.1.1", "192.168.1.2", 6, 20);
ok $pseudo_sum > 0, "IPv4 pseudo-header partial sum generated";

# Complete TCP checksum calculation over IPv4
my $tcp_syn = Buf.new(
    0x04, 0xd2, 0x00, 0x50, # Src port 1234, Dst port 80
    0x00, 0x00, 0x00, 0x01, # Seq = 1
    0x00, 0x00, 0x00, 0x00, # Ack = 0
    0x50, 0x02, 0x72, 0x10, # Header len = 20, Flags = SYN, Win = 29200
    0x00, 0x00, 0x00, 0x00  # Checksum zeroed, Urgent = 0
);
my $tcp_cksum = tcp-checksum-ipv4("10.0.0.1", "10.0.0.2", $tcp_syn);
ok $tcp_cksum > 0, "TCP checksum over IPv4 pseudo header computed successfully";

# UDP checksum calculation
my $udp_datagram = Buf.new(
    0x04, 0xd2, 0x00, 0x35, # Src port 1234, Dst port 53
    0x00, 0x0c, 0x00, 0x00, # Len = 12, Checksum zeroed
    0xaa, 0xbb, 0xcc, 0xdd  # 4 bytes payload
);
my $udp_cksum = udp-checksum-ipv4("192.168.1.10", "192.168.1.1", $udp_datagram);
ok $udp_cksum > 0, "UDP checksum computed successfully";
isnt $udp_cksum, 0, "UDP checksum preserves RFC 768 non-zero invariant";
