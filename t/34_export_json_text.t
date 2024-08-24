use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Export::Text;
use Sigil::Export::JSON;
use Sigil::Export::HexDump;
use Sigil::Export::CSV;

plan 12;

# Setup mock packet
my $raw = Buf.new("HELLO_EXPORT_TEST".encode('ascii'));
my $pkt = Sigil::Core::Packet.new(
    :raw($raw),
    :packet-id(42),
    :timestamp(1700000000.123456e0),
    :wire-length($raw.elems),
    :capture-length($raw.elems)
);

my $ip-fl = Sigil::Core::FieldList.new;
$ip-fl.add(Sigil::Core::AddressField.new(:name("Source IP"), :key("ip.src"), :value("192.168.1.1"), :address-type("ipv4")));
$ip-fl.add(Sigil::Core::AddressField.new(:name("Destination IP"), :key("ip.dst"), :value("192.168.1.2"), :address-type("ipv4")));
my $ip-layer = Sigil::Core::Layer.new(:name("IPv4"), :fields($ip-fl), :header-length(20));
$pkt.push-layer($ip-layer);

# 1. Text Formatter
{
    my $text-fmt = Sigil::Export::Text.new;
    my $hdr = $text-fmt.header;
    ok $hdr.contains("Source"), "Text header includes Source column";

    my $line = $text-fmt.format-packet($pkt);
    ok $line.contains("42"), "Text line contains packet ID 42";
    ok $line.contains("192.168.1.1"), "Text line contains source IP";

    my $tree-fmt = Sigil::Export::Text.new(:show-tree(True));
    my $tree = $tree-fmt.format-packet($pkt);
    ok $tree.contains("IPv4"), "Tree view contains IPv4 layer header";
}

# 2. JSON Formatter
{
    my $json-fmt = Sigil::Export::JSON.new(:ndjson(True));
    my $json-str = $json-fmt.format-packet($pkt);
    ok $json-str.starts-with('{') && $json-str.ends-with('}'), "JSON output is a valid JSON object";
    ok $json-str.contains('"packet_id":42'), "JSON contains packet_id key with numeric value";
    ok $json-str.contains('"ip.src"'), "JSON contains deep field key ip.src";

    # Pretty print
    my $pretty-fmt = Sigil::Export::JSON.new(:pretty(True));
    my $pretty-str = $pretty-fmt.format-packet($pkt);
    ok $pretty-str.contains("\n"), "Pretty JSON contains newlines";
}

# 3. HexDump Formatter
{
    my $hex-fmt = Sigil::Export::HexDump.new;
    my $dump = $hex-fmt.format-packet($pkt);
    ok $dump.contains("00000000"), "Hex dump starts with 00000000 offset";
    ok $dump.contains("HELLO_EXPORT_TES"), "Hex dump displays ASCII printable characters";
}

# 4. CSV Formatter
{
    my $csv-fmt = Sigil::Export::CSV.new;
    is $csv-fmt.header, "id,timestamp,src,dst,srcport,dstport,protocol,length", "CSV header columns match";

    my $row = $csv-fmt.format-packet($pkt);
    ok $row.starts-with("42,"), "CSV row starts with packet ID";
}

done-testing;
