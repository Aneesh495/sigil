# Test suite for Sigil::Grammar::Protocol::VLAN
use Test;
use Sigil::Grammar::Protocol::VLAN;
use Sigil::Types;

plan 8;

# 802.1Q tag: PCP = 5 (0b101), DEI = 0, VID = 4094 (0x0FFE) -> TCI = 0xaffe, EtherType = 0x0800
my $vlan_raw = Buf.new(
    0xaf, 0xfe, # TCI
    0x08, 0x00, # Encapsulated EtherType IPv4
    0x45, 0x00  # Payload start
);

my $layer = Sigil::Grammar::Protocol::VLAN.dissect($vlan_raw);
is $layer.name, "VLAN", "Layer identified as VLAN";
is $layer.status, STATUS_OK, "Dissection status OK";
is $layer.header-length, 4, "Header length 4 bytes";
is $layer.val("vlan.pcp"), 5, "Priority Code Point decoded as 5";
is $layer.val("vlan.dei"), False, "Drop eligible indicator is False";
is $layer.val("vlan.id"), 4094, "VLAN ID decoded as 4094";
is $layer.next-protocol, 0x0800, "Next protocol is IPv4";

# Truncated VLAN header
my $trunc = Buf.new(0x01, 0x02);
my $l_trunc = Sigil::Grammar::Protocol::VLAN.dissect($trunc);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated VLAN header yields STATUS_TRUNCATED";
