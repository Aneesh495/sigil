# Test suite for Sigil::Grammar::Protocol::MQTT
use Test;
use Sigil::Grammar::Protocol::MQTT;
use Sigil::Types;

plan 11;

# MQTT PUBLISH: Topic "sensors/temp", QoS 1, Packet ID 42, Payload "23.5"
# Byte 0: Type 3 (PUBLISH), Flags: QoS 1 -> 0x32
# Topic "sensors/temp" len = 12
# Remaining length: 2 + 12 + 2 + 4 = 20 bytes
my $mqtt_pub = Buf.new(
    0x32,                               # Type=PUBLISH, QoS=1
    20,                                 # Remaining length 20
    0x00, 0x0c,                         # Topic len = 12
    # "sensors/temp"
    0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x2f, 0x74, 0x65, 0x6d, 0x70,
    0x00, 0x2a,                         # Packet ID = 42
    # Payload "23.5"
    0x32, 0x33, 0x2e, 0x35
);

my $layer = Sigil::Grammar::Protocol::MQTT.dissect($mqtt_pub);
is $layer.name, "MQTT", "Layer identified as MQTT";
is $layer.status, STATUS_OK, "Status OK";
is $layer.val("mqtt.msgtype"), 3, "Control packet type is 3 (PUBLISH)";
is $layer.val("mqtt.flags.qos"), 1, "QoS level is 1";
is $layer.val("mqtt.topic"), "sensors/temp", "Topic parsed as 'sensors/temp'";
is $layer.val("mqtt.pkt_id"), 42, "Packet ID parsed as 42";
ok $layer.display-name.contains("Topic=sensors/temp"), "Display name contains topic";

# MQTT PINGREQ (Type 12, Remaining Length 0)
my $mqtt_ping = Buf.new(0xc0, 0x00);
my $l_ping = Sigil::Grammar::Protocol::MQTT.dissect($mqtt_ping);
is $l_ping.val("mqtt.msgtype"), 12, "Type is 12 (PINGREQ)";
is $l_ping.val("mqtt.len"), 0, "Remaining length is 0";
ok $l_ping.display-name.contains("PINGREQ"), "Display name contains PINGREQ";

# Truncated MQTT packet (< 2 bytes)
my $trunc_raw = Buf.new(0x30);
my $l_trunc = Sigil::Grammar::Protocol::MQTT.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated MQTT yields STATUS_TRUNCATED";
