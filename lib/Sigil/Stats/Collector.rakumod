# Sigil::Stats::Collector - Unified telemetry aggregation engine
#
# Orchestrates protocol counters, log-linear distribution histograms, heavy hitter
# talker tracking, and real-time security anomaly inspection.

unit class Sigil::Stats::Collector;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Stats::Counter;
use Sigil::Stats::Histogram;
use Sigil::Stats::TopTalkers;
use Sigil::Stats::Anomaly;

has Sigil::Stats::Counter $.counter;
has Sigil::Stats::Histogram $.packet-size-hist;
has Sigil::Stats::Histogram $.inter-arrival-hist;
has Sigil::Stats::TopTalkers $.top-ips;
has Sigil::Stats::TopTalkers $.top-conversations;
has Sigil::Stats::Anomaly $.anomaly-detector;

has Num $.last-packet-time = 0e0;

submethod BUILD() {
    $!counter = Sigil::Stats::Counter.new;
    $!packet-size-hist = Sigil::Stats::Histogram.new(:name("packet_size"), :bounds([64, 128, 256, 512, 1024, 1518, 9000]));
    $!inter-arrival-hist = Sigil::Stats::Histogram.new(:name("inter_arrival_ms"), :bounds([1, 5, 10, 50, 100, 500, 1000]));
    $!top-ips = Sigil::Stats::TopTalkers.new(:capacity(500));
    $!top-conversations = Sigil::Stats::TopTalkers.new(:capacity(500));
    $!anomaly-detector = Sigil::Stats::Anomaly.new;
}

# Record a dissected packet across all metrics subsystems
method record(Sigil::Core::Packet $pkt, Num $timestamp = 0e0 --> List) {
    my $ts = $timestamp > 0e0 ?? $timestamp !! now.Num;

    # 1. Update basic counters
    $!counter.record($pkt, $ts);

    # 2. Update packet size histogram
    $!packet-size-hist.record($pkt.length);

    # 3. Update inter-arrival time histogram
    if $!last-packet-time > 0e0 && $ts >= $!last-packet-time {
        my $delta-ms = ($ts - $!last-packet-time) * 1000e0;
        $!inter-arrival-hist.record($delta-ms);
    }
    $!last-packet-time = $ts;

    # 4. Update top talkers
    my $src = $pkt.val("ip.src") // $pkt.val("ipv6.src") // "";
    my $dst = $pkt.val("ip.dst") // $pkt.val("ipv6.dst") // "";

    if $src ne "" {
        $!top-ips.observe($src, $pkt.length);
    }
    if $src ne "" && $dst ne "" {
        my ($ep1, $ep2) = ($src le $dst) ?? ($src, $dst) !! ($dst, $src);
        $!top-conversations.observe("$ep1 <-> $ep2", $pkt.length);
    }

    # 5. Security anomaly inspection
    my @alerts = $!anomaly-detector.inspect($pkt, $ts);

    return @alerts;
}

# Export full metrics snapshot to dictionary
method to-hash(--> Hash) {
    return {
        total_packets    => $!counter.total-packets,
        total_bytes      => $!counter.total-bytes,
        pps              => $!counter.pps,
        mbps             => $!counter.mbps,
        packet_size_p50  => $!packet-size-hist.p50,
        packet_size_p99  => $!packet-size-hist.p99,
        top_talkers      => $!top-ips.top(10),
        top_flows        => $!top-conversations.top(10),
        alerts_count     => $!anomaly-detector.alert-count
    };
}

# Formatted multi-section telemetry report
method report(--> Str) {
    my @sections;
    @sections.push("=== SIGIL TELEMETRY & FORENSICS REPORT ===");
    @sections.push($!counter.summary);
    @sections.push("\nPacket Size Distribution (bytes):");
    @sections.push($!packet-size-hist.ascii-chart(35));
    @sections.push("\nTop Talker IP Addresses (by volume):");
    @sections.push($!top-ips.summary(5));
    @sections.push("\nTop Conversations (by volume):");
    @sections.push($!top-conversations.summary(5));

    if $!anomaly-detector.alert-count > 0 {
        @sections.push("\nSecurity Alerts:");
        @sections.push($!anomaly-detector.summary);
    }

    return @sections.join("\n");
}
