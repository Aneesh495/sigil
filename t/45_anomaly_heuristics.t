use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Stats::Anomaly;

plan 8;

my $detector = Sigil::Stats::Anomaly.new(:port-scan-threshold(5));

sub make-pkt(Int $flags, Int $dport, Str $src = "192.168.1.50" --> Sigil::Core::Packet) {
    my $pkt = Sigil::Core::Packet.new(:raw(Buf.new(0 xx 64)));

    my $ip-fl = Sigil::Core::FieldList.new;
    $ip-fl.add(Sigil::Core::AddressField.new(:name("Source IP"), :key("ip.src"), :value($src), :address-type("ipv4")));
    $ip-fl.add(Sigil::Core::AddressField.new(:name("Destination IP"), :key("ip.dst"), :value("10.0.0.1"), :address-type("ipv4")));
    $pkt.push-layer(Sigil::Core::Layer.new(:name("IPv4"), :fields($ip-fl)));

    my $tcp-fl = Sigil::Core::FieldList.new;
    $tcp-fl.add(Sigil::Core::IntField.new(:name("Source Port"), :key("tcp.srcport"), :value(40000)));
    $tcp-fl.add(Sigil::Core::IntField.new(:name("Destination Port"), :key("tcp.dstport"), :value($dport)));
    $tcp-fl.add(Sigil::Core::IntField.new(:name("Flags"), :key("tcp.flags"), :value($flags)));
    $pkt.push-layer(Sigil::Core::Layer.new(:name("TCP"), :fields($tcp-fl)));

    return $pkt;
}

# 1. Null scan alert (flags == 0)
{
    my $null-pkt = make-pkt(0, 80);
    my @alerts = $detector.inspect($null-pkt);
    is @alerts.elems, 1, "Null scan generates 1 alert";
    is @alerts[0]<type>, "TCP_NULL_SCAN", "Alert type is TCP_NULL_SCAN";
    is @alerts[0]<severity>, "HIGH", "Severity is HIGH";
}

# 2. Xmas scan alert (FIN + PSH + URG)
{
    my $xmas-flags = TCP_FIN +| TCP_PSH +| TCP_URG;
    my $xmas-pkt = make-pkt($xmas-flags, 22);
    my @alerts = $detector.inspect($xmas-pkt);
    is @alerts.elems, 1, "Xmas scan generates 1 alert";
    is @alerts[0]<type>, "TCP_XMAS_SCAN", "Alert type is TCP_XMAS_SCAN";
}

# 3. Illegal SYN+FIN combination
{
    my $syn-fin = make-pkt(TCP_SYN +| TCP_FIN, 80);
    my @alerts = $detector.inspect($syn-fin);
    ok @alerts.grep(*<type> eq "TCP_SYN_FIN_ANOMALY"), "SYN+FIN flags generate critical alert";
}

# 4. Vertical port scan trigger
{
    my $scanner-ip = "192.168.1.99";
    my @scan-alerts;
    for 1..5 -> $p {
        my $pkt = make-pkt(TCP_SYN, 1000 + $p, $scanner-ip);
        my @al = $detector.inspect($pkt);
        @scan-alerts.append(@al) if @al.elems > 0;
    }
    ok @scan-alerts.grep(*<type> eq "VERTICAL_PORT_SCAN"), "Scanning 5 distinct ports triggers VERTICAL_PORT_SCAN";
    ok $detector.alert-count >= 4, "Total alert log records anomaly events";
}

done-testing;
