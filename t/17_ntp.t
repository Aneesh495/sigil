# Test suite for Sigil::Grammar::Protocol::NTP
use Test;
use Sigil::Grammar::Protocol::NTP;
use Sigil::Types;

plan 10;

# Standard 48-byte NTP v4 Server packet:
# LI = 0, VN = 4, Mode = 4 (Server) -> Byte 0 = (0 << 6) | (4 << 3) | 4 = 0x24
# Stratum = 1 (Primary reference)
# Poll = 6 (64 seconds), Precision = -20 (~1 microsecond)
# Root delay = 0, Root dispersion = 0.001s
# RefID = "GPS "
# Timestamps: 64-bit (seconds since 1900 + fraction)
my @ntp_bytes = (
    0x24,                               # LI=0, VN=4, Mode=4
    0x01,                               # Stratum 1
    0x06,                               # Poll 6
    0xec,                               # Precision -20 (signed 8-bit = 236 = 0xEC)
    0x00, 0x00, 0x00, 0x00,             # Root delay 0
    0x00, 0x00, 0x00, 0x10,             # Root dispersion
    0x47, 0x50, 0x53, 0x20              # RefID "GPS "
);

# Add 4 timestamps: 4 x 8 = 32 bytes
# Timestamp: ~1700000000 UNIX = ~3908988800 NTP = 0xE8F9B780
for 1..4 {
    @ntp_bytes.push(0xe8, 0xf9, 0xb7, 0x80, 0x12, 0x34, 0x56, 0x78);
}

my $ntp_raw = Buf.new(@ntp_bytes);

my $layer = Sigil::Grammar::Protocol::NTP.dissect($ntp_raw);
is $layer.name, "NTP", "Layer identified as NTP";
is $layer.status, STATUS_OK, "Status OK";
is $layer.val("ntp.flags.li"), 0, "Leap indicator is 0 (No warning)";
is $layer.val("ntp.flags.vn"), 4, "Version is 4";
is $layer.val("ntp.flags.mode"), 4, "Mode is 4 (Server)";
is $layer.val("ntp.stratum"), 1, "Stratum is 1 (Primary)";
is $layer.val("ntp.refid"), "GPS", "Reference ID parsed as 'GPS'";
ok $layer.display-name.contains("Stratum 1"), "Display name contains Stratum";
ok $layer.display-name.contains("GPS"), "Display name contains GPS RefID";

# Truncated NTP (< 48 bytes)
my $trunc_raw = Buf.new(0x24, 0x01, 0x06);
my $l_trunc = Sigil::Grammar::Protocol::NTP.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated NTP yields STATUS_TRUNCATED";
