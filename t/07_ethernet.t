# Test suite for Sigil::Grammar::Protocol::Ethernet
use Test;
use Sigil::Grammar::Protocol::Ethernet;
use Sigil::Types;

plan 11;

# Standard Ethernet II frame (14 bytes header + 4 bytes payload)
my $eth_raw = Buf.new(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, # Dst MAC
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, # Src MAC
    0x08, 0x00,                         # EtherType = 0x0800 (IPv4)
    0xde, 0xad, 0xbe, 0xef              # Payload
);

my $layer = Sigil::Grammar::Protocol::Ethernet.dissect($eth_raw);
is $layer.name, "Ethernet", "Layer identified as Ethernet";
is $layer.status, STATUS_OK, "Dissection status OK";
is $layer.header-length, 14, "Header length 14 bytes";
is $layer.payload-length, 4, "Payload length 4 bytes";
is $layer.val("eth.dst"), "00:11:22:33:44:55", "Destination MAC decoded";
is $layer.val("eth.src"), "66:77:88:99:aa:bb", "Source MAC decoded";
is $layer.val("eth.type"), 0x0800, "EtherType decoded as IPv4";
is $layer.next-protocol, 0x0800, "Next protocol selector set to 0x0800";

# 802.1Q VLAN tagged frame (18 bytes header)
# TCI: Priority 3 (0b011), CFI 0, VID 200 (0x00C8) -> 0x60C8
my $vlan_raw = Buf.new(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0x81, 0x00,                         # VLAN TPID
    0x60, 0xc8,                         # TCI: Pri 3, VID 200
    0x08, 0x00,                         # Inner EtherType IPv4
    0xde, 0xad                          # Payload
);
my $vlan_layer = Sigil::Grammar::Protocol::Ethernet.dissect($vlan_raw);
is $vlan_layer.header-length, 18, "VLAN tagged header length 18 bytes";
is $vlan_layer.val("vlan.id"), 200, "VLAN ID 200 extracted";

# Truncated frame
my $trunc_raw = Buf.new(0x00, 0x11, 0x22);
my $trunc_layer = Sigil::Grammar::Protocol::Ethernet.dissect($trunc_raw);
is $trunc_layer.status, STATUS_TRUNCATED, "Truncated frame yields STATUS_TRUNCATED";
