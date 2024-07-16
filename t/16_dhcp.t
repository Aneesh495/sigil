# Test suite for Sigil::Grammar::Protocol::DHCP
use Test;
use Sigil::Grammar::Protocol::DHCP;
use Sigil::Types;

plan 11;

# Construct valid 240+ byte DHCPDISCOVER message:
# Op 1, HType 1, HLen 6, Hops 0, XID 0x3903f326, Secs 0, Flags 0x8000 (Broadcast)
# Client MAC: 00:0b:82:01:fc:42
# Magic Cookie: 0x63 0x82 0x53 0x63
# Option 53: DHCPDISCOVER (len 1, val 1)
# Option 12: Host Name "laptop" (len 6)
# Option 255: End
my @dhcp_bytes = (
    0x01, 0x01, 0x06, 0x00,             # Op 1, HType 1, HLen 6, Hops 0
    0x39, 0x03, 0xf3, 0x26,             # XID 0x3903f326
    0x00, 0x00,                         # Secs 0
    0x80, 0x00,                         # Flags 0x8000 (Broadcast)
    0, 0, 0, 0,                         # ciaddr 0.0.0.0
    0, 0, 0, 0,                         # yiaddr 0.0.0.0
    0, 0, 0, 0,                         # siaddr 0.0.0.0
    0, 0, 0, 0,                         # giaddr 0.0.0.0
    # chaddr (16 bytes)
    0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
);

# Pad 64 bytes sname + 128 bytes file = 192 zero bytes
for 1..192 { @dhcp_bytes.push(0); }

# Magic cookie (4 bytes: 99, 130, 83, 99)
@dhcp_bytes.push(0x63, 0x82, 0x53, 0x63);

# Option 53 (DHCP Message Type = 1 Discover)
@dhcp_bytes.push(53, 1, 1);

# Option 12 (Host Name = "laptop")
@dhcp_bytes.push(12, 6);
for "laptop".encode('ascii').list { @dhcp_bytes.push($_); }

# Option 255 (End)
@dhcp_bytes.push(255);

my $dhcp_raw = Buf.new(@dhcp_bytes);

my $layer = Sigil::Grammar::Protocol::DHCP.dissect($dhcp_raw);
is $layer.name, "DHCP", "Layer identified as DHCP";
is $layer.status, STATUS_OK, "Status OK";
is $layer.val("dhcp.op"), 1, "Opcode is 1 (BootRequest)";
is $layer.val("dhcp.xid"), 0x3903f326, "Transaction ID parsed as 0x3903f326";
is $layer.val("dhcp.flags.broadcast"), True, "Broadcast flag is True";
is $layer.val("dhcp.chaddr"), "00:0b:82:01:fc:42", "Client MAC address parsed";
is $layer.val("dhcp.magic"), 0x63825363, "Magic cookie verified as 0x63825363";
is $layer.val("dhcp.option.type"), 1, "Option 53 parsed as 1 (DHCPDISCOVER)";
is $layer.val("dhcp.option.hostname"), "laptop", "Option 12 Host Name parsed as 'laptop'";
ok $layer.display-name.contains("DHCPDISCOVER"), "Display name contains message type";

# Truncated DHCP (< 240 bytes)
my $trunc_raw = Buf.new(1..100);
my $l_trunc = Sigil::Grammar::Protocol::DHCP.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated DHCP yields STATUS_TRUNCATED";
