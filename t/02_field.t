# Test suite for Sigil::Core::Field and FieldList
use Test;
use Sigil::Core::Field;

plan 16;

# IntField
my $int_f = Sigil::Core::IntField.new(
    :name("Source Port"),
    :key("tcp.srcport"),
    :offset-bytes(0),
    :length-bytes(2),
    :value(443),
    :radix("dec")
);
is $int_f.format-value, "443", "IntField formats decimal value correctly";
is $int_f.to-hash<key>, "tcp.srcport", "IntField to-hash preserves filter key";

my $hex_f = Sigil::Core::IntField.new(
    :name("EtherType"),
    :key("eth.type"),
    :offset-bytes(12),
    :length-bytes(2),
    :value(0x0800),
    :radix("hex"),
    :bit-width(16)
);
is $hex_f.format-value, "0x0800", "IntField formats hexadecimal with zero padding";

# BitField
my $bit_f = Sigil::Core::BitField.new(
    :name("Version"),
    :key("ip.version"),
    :offset-bytes(0),
    :length-bytes(1),
    :bit-offset(0),
    :bit-length(4),
    :value(4)
);
is $bit_f.format-value, "4 (bits 0..3)", "BitField formats bit offset and range";

# FlagField
my $flag_set = Sigil::Core::FlagField.new(
    :name("SYN"),
    :key("tcp.flags.syn"),
    :offset-bytes(13),
    :length-bytes(1),
    :mask(0x02),
    :is-set(True)
);
is $flag_set.format-value, "Set (1)", "FlagField formats active flag status";

my $flag_unset = Sigil::Core::FlagField.new(
    :name("FIN"),
    :key("tcp.flags.fin"),
    :offset-bytes(13),
    :length-bytes(1),
    :mask(0x01),
    :is-set(False)
);
is $flag_unset.format-value, "Not set (0)", "FlagField formats inactive flag status";

# EnumField
my %proto_names = (1 => "ICMP", 6 => "TCP", 17 => "UDP");
my $enum_f = Sigil::Core::EnumField.new(
    :name("Next Protocol"),
    :key("ip.proto"),
    :offset-bytes(9),
    :length-bytes(1),
    :value(6),
    :name-map(%proto_names)
);
is $enum_f.format-value, "TCP (6)", "EnumField resolves symbolic name for registered code";

my $enum_unknown = Sigil::Core::EnumField.new(
    :name("Next Protocol"),
    :key("ip.proto"),
    :offset-bytes(9),
    :length-bytes(1),
    :value(99),
    :name-map(%proto_names)
);
is $enum_unknown.format-value, "Unknown (99)", "EnumField formats unknown numeric code gracefully";

# AddressField
my $mac_f = Sigil::Core::AddressField.new(
    :name("Source MAC"),
    :key("eth.src"),
    :value("aa:bb:cc:dd:ee:ff"),
    :address-type("mac")
);
is $mac_f.format-value, "aa:bb:cc:dd:ee:ff", "AddressField returns formatted MAC address";

# StringField
my $str_f = Sigil::Core::StringField.new(
    :name("HTTP Method"),
    :key("http.method"),
    :value("GET")
);
is $str_f.format-value, '"GET"', "StringField encloses value in double quotes";

# BytesField
my $bytes_f = Sigil::Core::BytesField.new(
    :name("Payload"),
    :key("tcp.payload"),
    :raw(Buf.new(0xde, 0xad, 0xbe, 0xef))
);
is $bytes_f.format-value, "de ad be ef", "BytesField formats raw hex representation";

# FieldList container operations
my $fl = Sigil::Core::FieldList.new;
$fl.add($int_f);
$fl.add($hex_f);
$fl.add($bit_f);
is $fl.elems, 3, "FieldList records element count";
ok $fl.has-key("tcp.srcport"), "FieldList indexes field keys for fast lookup";
is $fl.get("tcp.srcport").value, 443, "FieldList retrieves field by key";

my $tree_str = $fl.to-tree-str(4);
ok $tree_str.contains("Source Port"), "Tree string contains field names";
ok $tree_str.contains("0x0800"), "Tree string contains formatted field values";
