# Test suite for Sigil::Grammar::Protocol::BGP
use Test;
use Sigil::Grammar::Protocol::BGP;
use Sigil::Types;

plan 11;

# BGP OPEN message:
# Marker (16 bytes 0xFF)
# Length = 29 bytes (19 base + 10 OPEN)
# Type = 1 (OPEN)
# Version = 4, My AS = 65001 (0xFDE9), Hold Time = 180, BGP ID = 10.0.0.1, OptParamLen = 0
my @open_bytes;
for 1..16 { @open_bytes.push(0xFF); }
@open_bytes.push(0x00, 0x1d);          # Length = 29
@open_bytes.push(0x01);                # Type = 1 (OPEN)
@open_bytes.push(0x04);                # Version = 4
@open_bytes.push(0xfd, 0xe9);          # AS 65001
@open_bytes.push(0x00, 0xb4);          # Hold Time = 180
@open_bytes.push(10, 0, 0, 1);         # BGP ID: 10.0.0.1
@open_bytes.push(0x00);                # OptParamLen = 0

my $bgp_open = Buf.new(@open_bytes);

my $layer = Sigil::Grammar::Protocol::BGP.dissect($bgp_open);
is $layer.name, "BGP", "Layer identified as BGP";
is $layer.status, STATUS_OK, "Status is OK with valid marker";
is $layer.val("bgp.type"), 1, "Message type is 1 (OPEN)";
is $layer.val("bgp.open.version"), 4, "BGP version is 4";
is $layer.val("bgp.open.as"), 65001, "Autonomous System parsed as 65001";
is $layer.val("bgp.open.hold_time"), 180, "Hold time parsed as 180s";
is $layer.val("bgp.open.id"), "10.0.0.1", "BGP Identifier parsed as 10.0.0.1";
ok $layer.display-name.contains("AS65001"), "Display name contains Autonomous System";

# BGP KEEPALIVE message: 16 bytes 0xFF, Len 19, Type 4
my @ka_bytes;
for 1..16 { @ka_bytes.push(0xFF); }
@ka_bytes.push(0x00, 0x13, 0x04);
my $bgp_ka = Buf.new(@ka_bytes);
my $l_ka = Sigil::Grammar::Protocol::BGP.dissect($bgp_ka);
is $l_ka.val("bgp.type"), 4, "Type is 4 (KEEPALIVE)";
ok $l_ka.display-name.contains("KEEPALIVE"), "Display name contains KEEPALIVE";

# Truncated BGP (< 19 bytes)
my $trunc_raw = Buf.new(0xFF, 0xFF, 0xFF);
my $l_trunc = Sigil::Grammar::Protocol::BGP.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated BGP yields STATUS_TRUNCATED";
