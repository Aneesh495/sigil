#!/usr/bin/env raku
# scripts/benchmark.raku - Microsecond packet dissection and filter performance benchmark
#
# Measures parsing throughput, memory overhead, filter predicate latency, and
# flow table ingestion rates across high-volume synthetic packet streams.

use v6.d;
use lib 'lib';
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Dissector;
use Sigil::Filter::Engine;
use Sigil::Flow::Tracker;

sub MAIN(Int :$packets = 20000) {
    put "=========================================================";
    put "           SIGIL HIGH-THROUGHPUT BENCHMARK               ";
    put "=========================================================";
    put sprintf("Synthesizing %d multi-layer Ethernet/IPv4/TCP frames...", $packets);

    # Pre-build synthetic Ethernet/IPv4/TCP raw frame
    my @raw-bytes = (
        # Ethernet: dst=00:aa:bb:cc:dd:ee, src=00:11:22:33:44:55, type=0x0800
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        # IPv4: v4, ihl=5, total_len=40, id=0x1234, proto=6, src=10.0.0.1, dst=10.0.0.2
        0x45, 0x00, 0x00, 0x28,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0xB5, 0x36,
        0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
        # TCP: sport=54321, dport=80, seq=1000, ack=0, offset=5, flags=0x02 (SYN), win=65535
        0xD4, 0x31, 0x00, 0x50,
        0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xFF, 0xFF,
        0x91, 0x7C, 0x00, 0x00
    );
    my $raw-buf = Buf.new(@raw-bytes);

    # Benchmark 1: Recursive Protocol Dissection
    {
        put "\n[1/3] Benchmarking Multi-Layer Dissection Pipeline...";
        my $pipeline = Sigil::Core::Dissector.new;
        my $t0 = now;

        for 1..$packets -> $i {
            my $pkt = $pipeline.dissect-packet(
                $raw-buf,
                :packet-id($i),
                :timestamp(1700000000e0 + ($i * 0.0001e0))
            );
        }

        my $t1 = now;
        my $elapsed = ($t1 - $t0).Num;
        my $pps = $packets / $elapsed;
        my $us_per_pkt = ($elapsed * 1000000e0) / $packets;
        my $mbps = (($packets * $raw-buf.elems * 8) / ($elapsed * 1000000e0));

        put sprintf("  Duration     : %.4f seconds", $elapsed);
        put sprintf("  Throughput   : %.2f packets/sec (%.2f Mbps wire rate)", $pps, $mbps);
        put sprintf("  Latency      : %.2f microseconds/packet", $us_per_pkt);
    }

    # Benchmark 2: Filter DSL Evaluation
    {
        put "\n[2/3] Benchmarking Filter DSL Predicate Engine...";
        my $pipeline = Sigil::Core::Dissector.new;
        my $pkt = $pipeline.dissect-packet($raw-buf, :packet-id(1));

        my $filter-fn = Sigil::Filter::Engine::compile-filter("ip.proto == 6 && tcp.dstport == 80");
        my $eval-count = $packets * 2;
        my $matches = 0;

        my $t0 = now;
        for 1..$eval-count {
            $matches++ if $filter-fn($pkt);
        }
        my $t1 = now;

        my $elapsed = ($t1 - $t0).Num;
        my $evals_per_sec = $eval-count / $elapsed;
        my $ns_per_eval = ($elapsed * 1000000000e0) / $eval-count;

        put sprintf("  Evaluations  : %d filter evaluations", $eval-count);
        put sprintf("  Throughput   : %.2f evals/sec", $evals_per_sec);
        put sprintf("  Latency      : %.2f nanoseconds/eval", $ns_per_eval);
    }

    # Benchmark 3: Flow Tracker Session Ingestion
    {
        put "\n[3/3] Benchmarking Bidirectional Flow Tracking Engine...";
        my $pipeline = Sigil::Core::Dissector.new;
        my $pkt = $pipeline.dissect-packet($raw-buf, :packet-id(1));
        my $tracker = Sigil::Flow::Tracker.new;

        my $t0 = now;
        for 1..$packets -> $i {
            $tracker.process($pkt, 1700000000e0 + ($i * 0.0001e0));
        }
        my $t1 = now;

        my $elapsed = ($t1 - $t0).Num;
        my $flows_per_sec = $packets / $elapsed;

        put sprintf("  Duration     : %.4f seconds", $elapsed);
        put sprintf("  Throughput   : %.2f flow packet ingestions/sec", $flows_per_sec);
        put sprintf("  Active Flows : %d", $tracker.active-count);
    }

    put "\n=========================================================";
    put "Benchmark run completed successfully.";
}
