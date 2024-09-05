use v6.d;
use Test;
use Sigil::Types;
use Sigil::Capture::Offline;
use Sigil::Core::Dissector;
use Sigil::Filter::Engine;
use Sigil::Flow::Tracker;
use Sigil::Stats::Collector;
use Sigil::Export::Text;
use Sigil::Export::JSON;
use Sigil::Export::CSV;

plan 16;

# 1. End-to-end HTTP session trace analysis
{
    my $driver = Sigil::Capture::Offline.new(:filepath("t/fixtures/http_session.pcap"));
    ok $driver.open(), "Opened http_session.pcap golden trace";

    my $pipeline = Sigil::Core::Dissector.new;
    my $tracker = Sigil::Flow::Tracker.new;
    my $collector = Sigil::Stats::Collector.new;

    my @packets;
    while $driver.next-packet() -> $raw {
        my $pkt = $pipeline.dissect-packet($raw);
        @packets.push($pkt);
        $tracker.process($pkt, $pkt.timestamp);
        $collector.record($pkt, $pkt.timestamp);
    }
    $driver.close();

    is @packets.elems, 6, "Captured exactly 6 packets in HTTP conversation";
    ok @packets[3].has-layer("HTTP"), "Packet #4 contains HTTP layer";
    is @packets[3].val("http.method"), "GET", "HTTP Request method is GET";
    is @packets[4].val("http.status_code"), 200, "HTTP Response status code is 200";

    # Flow tracker verification
    is $tracker.active-count, 1, "Tracked exactly 1 TCP conversation flow";
    my $session = $tracker.active-sessions[0];
    is $session.key.proto, "TCP", "Flow protocol is TCP";
    is $session.app-protocol, "HTTP", "Flow classified as HTTP application protocol";
    is $session.c2s-packets, 4, "Client sent 4 packets";
    is $session.s2c-packets, 2, "Server sent 2 packets";
}

# 2. End-to-end DNS query trace analysis
{
    my $driver = Sigil::Capture::Offline.new(:filepath("t/fixtures/dns_query.pcap"));
    ok $driver.open(), "Opened dns_query.pcap trace";

    my $pipeline = Sigil::Core::Dissector.new;
    my $raw = $driver.next-packet();
    my $pkt = $pipeline.dissect-packet($raw);
    $driver.close();

    ok $pkt.has-layer("DNS"), "Packet has DNS layer";
    is $pkt.val("dns.query.name"), "example.com", "Queried DNS domain name is example.com";
    is $pkt.val("dns.count.queries"), 1, "DNS query count is 1";
}

# 3. Export formatters integration on parsed trace
{
    my $driver = Sigil::Capture::Offline.new(:filepath("t/fixtures/http_session.pcap"));
    $driver.open();
    my $raw = $driver.next-packet();
    my $pkt = Sigil::Core::Dissector::dissect-packet($raw);
    $driver.close();

    my $csv = Sigil::Export::CSV.new.format-packet($pkt);
    ok $csv.contains("192.168.1.100"), "CSV export row contains client IP";

    my $json = Sigil::Export::JSON.new.format-packet($pkt);
    ok $json.contains('"key":"ip.proto"'), "JSON export contains IPv4 protocol key";
}

done-testing;
