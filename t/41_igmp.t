use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Layer;
use Sigil::Grammar::Protocol::IGMP;

plan 6;

my $dissector = Sigil::Grammar::Protocol::IGMP.new;

# Construct synthetic IGMPv2 Membership Report for multicast group 224.0.0.251 (mDNS)
my @bytes = (
    0x16,                   # Type = IGMPv2 Membership Report (0x16)
    0x64,                   # Max Response Time = 100 (10.0 sec)
    0x00, 0x00,             # Checksum
    224, 0, 0, 251          # Multicast Group Address = 224.0.0.251
);

my $raw = Buf.new(@bytes);
my $layer = $dissector.dissect($raw);

ok $layer.defined, "IGMP layer dissected successfully";
is $layer.status, STATUS_OK, "Dissection status is STATUS_OK";
is $layer.val("igmp.type"), 0x16, "Type is 0x16 (IGMPv2 Membership Report)";
is $layer.val("igmp.max_resp_time"), 100, "Max response time is 100";
is $layer.val("igmp.group_address"), "224.0.0.251", "Multicast Group Address is 224.0.0.251";
ok $layer.display-name.contains("224.0.0.251"), "Display name contains group address";

done-testing;
