use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Layer;
use Sigil::Grammar::Protocol::LLDP;

plan 8;

my $dissector = Sigil::Grammar::Protocol::LLDP.new;

# Construct synthetic LLDPDU frame with Chassis ID, Port ID, TTL, System Name, and End TLV
my @bytes;

# TLV 1: Chassis ID (Type=1, Len=7). Subtype=4 (MAC), MAC = 00:11:22:33:44:55
# TLV Header: (1 << 9) | 7 = 0x0207
@bytes.push(0x02, 0x07);
@bytes.push(0x04); # Subtype MAC
@bytes.push(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

# TLV 2: Port ID (Type=2, Len=5). Subtype=5 (Interface Name), Name = "eth0"
# TLV Header: (2 << 9) | 5 = 0x0405
@bytes.push(0x04, 0x05);
@bytes.push(0x05); # Subtype Interface Name
@bytes.append("eth0".encode('ascii').list);

# TLV 3: TTL (Type=3, Len=2). Seconds = 120 (0x0078)
# TLV Header: (3 << 9) | 2 = 0x0602
@bytes.push(0x06, 0x02);
@bytes.push(0x00, 0x78);

# TLV 5: System Name (Type=5, Len=8). Name = "switch01"
# TLV Header: (5 << 9) | 8 = 0x0A08
@bytes.push(0x0A, 0x08);
@bytes.append("switch01".encode('ascii').list);

# TLV 0: End of LLDPDU (Type=0, Len=0).
@bytes.push(0x00, 0x00);

my $raw = Buf.new(@bytes);
my $layer = $dissector.dissect($raw);

ok $layer.defined, "LLDP layer dissected successfully";
is $layer.status, STATUS_OK, "Dissection status is STATUS_OK";
is $layer.val("lldp.chassis.id"), "00:11:22:33:44:55", "Chassis MAC address decoded correctly";
is $layer.val("lldp.chassis.subtype"), 4, "Chassis subtype is MAC (4)";
is $layer.val("lldp.port.id"), "eth0", "Port ID is eth0";
is $layer.val("lldp.ttl"), 120, "Time to live is 120 seconds";
is $layer.val("lldp.system.name"), "switch01", "System name is switch01";
ok $layer.display-name.contains("switch01"), "Display name incorporates system name";

done-testing;
