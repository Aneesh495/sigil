use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Stats::TopTalkers;
use Sigil::Stats::Counter;
use Sigil::Stats::Histogram;
use Sigil::Stats::Collector;

plan 15;

# 1. TopTalkers with capacity 3
{
    my $tt = Sigil::Stats::TopTalkers.new(:capacity(3));

    # Feed 10 packets for Host A, 5 for Host B, 2 for Host C
    $tt.observe("Host-A", 10);
    $tt.observe("Host-B", 5);
    $tt.observe("Host-C", 2);

    my @top = $tt.top(3);
    is @top.elems, 3, "Retains 3 entries up to capacity";
    is @top[0]<key>, "Host-A", "Top 1 is Host-A";
    is @top[0]<count>, 10, "Host-A count is exact (10)";
    is @top[0]<max_error>, 0, "Host-A max error is 0";

    # Insert Host D: should evict lowest count (Host C with count 2)
    # Host D count becomes 2 + 1 = 3, with error 2
    $tt.observe("Host-D", 1);
    my @top_after = $tt.top(3);
    is @top_after[2]<key>, "Host-D", "Host D entered top 3 replacing evicted min entry";
    is @top_after[2]<count>, 3, "Host D estimated count is min + weight (2 + 1 = 3)";
    is @top_after[2]<max_error>, 2, "Host D bounded error recorded as 2";
}

# 2. Histogram percentiles and statistics
{
    my $hist = Sigil::Stats::Histogram.new(:name("test_latency"), :bounds([10, 50, 100, 500]));

    # Record 100 observations: 1..100
    for 1..100 -> $v {
        $hist.record($v);
    }

    is $hist.count, 100, "Histogram count is 100";
    is-approx $hist.min, 1e0, 1e-4, "Minimum value is 1.0";
    is-approx $hist.max, 100e0, 1e-4, "Maximum value is 100.0";
    is-approx $hist.mean, 50.5e0, 1e-4, "Mean value is 50.5";
    is-approx $hist.p50, 50e0, 2e0, "Median p50 is approximately 50";
    ok $hist.p90 > 85e0, "90th percentile is above 85";

    my $chart = $hist.ascii-chart(20);
    ok $chart.contains("#"), "ASCII chart renders distribution bars";
}

# 3. Collector integration
{
    my $coll = Sigil::Stats::Collector.new;
    my $raw = Buf.new(0 xx 64);
    my $pkt = Sigil::Core::Packet.new(:raw($raw), :packet-id(1));

    my $ip-fl = Sigil::Core::FieldList.new;
    $ip-fl.add(Sigil::Core::AddressField.new(:name("Source IP"), :key("ip.src"), :value("192.168.1.100"), :address-type("ipv4")));
    $ip-fl.add(Sigil::Core::AddressField.new(:name("Destination IP"), :key("ip.dst"), :value("8.8.8.8"), :address-type("ipv4")));
    my $ip-l = Sigil::Core::Layer.new(:name("IPv4"), :fields($ip-fl), :header-length(20), :payload-length(44));
    $pkt.push-layer($ip-l);

    $coll.record($pkt, 1000.0e0);

    my %snap = $coll.to-hash;
    is %snap<total_packets>, 1, "Collector recorded 1 packet";
}

done-testing;
