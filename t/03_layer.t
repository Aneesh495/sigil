# Test suite for Sigil::Core::Layer
use Test;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Types;

plan 11;

# Construct layer with fields
my $fl = Sigil::Core::FieldList.new;
$fl.add(Sigil::Core::IntField.new(
    :name("Source Port"),
    :key("tcp.srcport"),
    :offset-bytes(0),
    :length-bytes(2),
    :value(8080)
));
$fl.add(Sigil::Core::IntField.new(
    :name("Destination Port"),
    :key("tcp.dstport"),
    :offset-bytes(2),
    :length-bytes(2),
    :value(443)
));

my $layer = Sigil::Core::Layer.new(
    :name("TCP"),
    :display-name("Transmission Control Protocol"),
    :offset(14),
    :header-length(20),
    :payload-length(100),
    :fields($fl),
    :status(STATUS_OK),
    :next-protocol("TLS")
);

is $layer.name, "TCP", "Layer name matches assigned protocol";
is $layer.display-name, "Transmission Control Protocol", "Display name matches";
is $layer.offset, 14, "Offset recorded accurately";
is $layer.header-length, 20, "Header length recorded";
is $layer.payload-length, 100, "Payload length recorded";

# Field lookups
ok $layer.field("tcp.srcport").defined, "Field lookup by selector key succeeds";
is $layer.val("tcp.srcport"), 8080, "Value accessor retrieves parsed numeric port";
nok $layer.val("tcp.nonexistent").defined, "Nonexistent field key returns undefined";

# Summary and tree output
my $sum = $layer.summary;
ok $sum.contains("TCP"), "Summary contains protocol label";
ok $sum.contains("8080"), "Summary contains field values";

# JSON hash conversion
my %h = $layer.to-hash;
is %h<name>, "TCP", "Exported hash contains protocol name";
