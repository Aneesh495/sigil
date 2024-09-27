use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Filter::Engine;

plan 10;

sub make-test-packet(Str $src, Str $dst, Int $sport, Int $dport, Int $proto --> Sigil::Core::Packet) {
    my $pkt = Sigil::Core::Packet.new(:raw(Buf.new(0 xx 64)));

    my $ip-fl = Sigil::Core::FieldList.new;
    $ip-fl.add(Sigil::Core::AddressField.new(:name("Source IP"), :key("ip.src"), :value($src), :address-type("ipv4")));
    $ip-fl.add(Sigil::Core::AddressField.new(:name("Destination IP"), :key("ip.dst"), :value($dst), :address-type("ipv4")));
    $ip-fl.add(Sigil::Core::IntField.new(:name("Protocol"), :key("ip.proto"), :value($proto)));
    $pkt.push-layer(Sigil::Core::Layer.new(:name("IPv4"), :fields($ip-fl)));

    my $tcp-fl = Sigil::Core::FieldList.new;
    $tcp-fl.add(Sigil::Core::IntField.new(:name("Source Port"), :key("tcp.srcport"), :value($sport)));
    $tcp-fl.add(Sigil::Core::IntField.new(:name("Destination Port"), :key("tcp.dstport"), :value($dport)));
    $pkt.push-layer(Sigil::Core::Layer.new(:name("TCP"), :fields($tcp-fl)));

    return $pkt;
}

my $pkt1 = make-test-packet("192.168.1.10", "10.0.0.1", 54321, 80, 6);
my $pkt2 = make-test-packet("172.16.0.5", "10.0.0.2", 45000, 443, 6);

# 1. Logical AND
{
    my $fn = Sigil::Filter::Engine::compile-filter("tcp.dstport == 80 && ip.proto == 6");
    ok $fn($pkt1), "pkt1 matches dstport 80 AND proto 6";
    nok $fn($pkt2), "pkt2 fails dstport 80";
}

# 2. Logical OR
{
    my $fn = Sigil::Filter::Engine::compile-filter("tcp.dstport == 80 || tcp.dstport == 443");
    ok $fn($pkt1), "pkt1 matches port 80 in OR condition";
    ok $fn($pkt2), "pkt2 matches port 443 in OR condition";
}

# 3. Numeric range comparisons
{
    my $fn = Sigil::Filter::Engine::compile-filter("tcp.srcport >= 50000 && tcp.srcport <= 60000");
    ok $fn($pkt1), "pkt1 port 54321 is inside range [50000..60000]";
    nok $fn($pkt2), "pkt2 port 45000 is outside range [50000..60000]";
}

# 4. Inequality operator
{
    my $fn = Sigil::Filter::Engine::compile-filter("tcp.dstport != 443");
    ok $fn($pkt1), "pkt1 dstport 80 != 443 evaluates True";
    nok $fn($pkt2), "pkt2 dstport 443 != 443 evaluates False";
}

# 5. Nonexistent field safety
{
    my $fn = Sigil::Filter::Engine::compile-filter("nonexistent.field == 123");
    nok $fn($pkt1), "Missing field lookup evaluates safely to False without exception";
}

# 6. Negation NOT operator
{
    my $fn = Sigil::Filter::Engine::compile-filter("!(tcp.dstport == 443)");
    ok $fn($pkt1), "Negation of false condition is True";
}

done-testing;
