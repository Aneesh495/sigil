# Sigil::CLI::Runner - Command execution dispatcher and toolchain orchestrator
#
# Connects capture drivers, recursive dissectors, filter evaluation engines,
# flow reassembly trackers, and telemetry exporters.

unit class Sigil::CLI::Runner;

use Sigil::Types;
use Sigil::CLI::Options;
use Sigil::Capture::Offline;
use Sigil::Core::Dissector;
use Sigil::Filter::Engine;
use Sigil::Flow::Tracker;
use Sigil::Stats::Collector;
use Sigil::Stats::Entropy;
use Sigil::PCAP::PCAPNG;
use Sigil::Export::Text;
use Sigil::Export::JSON;
use Sigil::Export::HexDump;
use Sigil::Export::CSV;

# Main runner entrypoint
method run(Sigil::CLI::Options $opts --> Int) {
    if $opts.show-help {
        print $opts.usage;
        return 0;
    }

    given $opts.subcommand {
        when "dissect" { return self.run-dissect($opts); }
        when "flow"    { return self.run-flow($opts); }
        when "stats"   { return self.run-stats($opts); }
        when "entropy" { return self.run-entropy($opts); }
        when "pcapng"  { return self.run-pcapng($opts); }
        when "filter"  { return self.run-filter($opts); }
        default {
            note "Unknown subcommand: " ~ $opts.subcommand;
            print $opts.usage;
            return 1;
        }
    }
}

# Subcommand: dissect
method run-dissect(Sigil::CLI::Options $opts --> Int) {
    if $opts.filepath eq "" {
        note "Error: No trace file specified. Use -r <trace.pcap>";
        return 1;
    }

    my $driver = Sigil::Capture::Offline.new(
        :filepath($opts.filepath),
        :rate-multiplier($opts.rate-multiplier)
    );

    unless $driver.open() {
        note "Error: Failed to open trace file " ~ $opts.filepath;
        return 1;
    }

    my $filter-fn;
    if $opts.filter-expr ne "" {
        $filter-fn = Sigil::Filter::Engine::compile-filter($opts.filter-expr);
    }

    my $formatter;
    given $opts.format {
        when "json"   { $formatter = Sigil::Export::JSON.new(:ndjson(False), :pretty(True)); }
        when "ndjson" { $formatter = Sigil::Export::JSON.new(:ndjson(True)); }
        when "csv"    { $formatter = Sigil::Export::CSV.new; }
        when "hex"    { $formatter = Sigil::Export::HexDump.new; }
        default       { $formatter = Sigil::Export::Text.new(:show-tree($opts.show-tree)); }
    }

    my $hdr = $formatter.header;
    print $hdr ~ "\n" if $hdr ne "";

    my $processed = 0;
    while $driver.next-packet() -> $raw-pkt {
        my $pkt = Sigil::Core::Dissector::dissect-packet($raw-pkt);

        # Filter check
        if $filter-fn.defined {
            next unless $filter-fn($pkt);
        }

        print $formatter.format-packet($pkt) ~ "\n";
        $processed++;

        if $opts.packet-limit > 0 && $processed >= $opts.packet-limit {
            last;
        }
    }

    my $ftr = $formatter.footer;
    print $ftr ~ "\n" if $ftr ne "";

    $driver.close();
    return 0;
}

# Subcommand: flow
method run-flow(Sigil::CLI::Options $opts --> Int) {
    if $opts.filepath eq "" {
        note "Error: No trace file specified. Use -r <trace.pcap>";
        return 1;
    }

    my $driver = Sigil::Capture::Offline.new(:filepath($opts.filepath));
    unless $driver.open() {
        note "Error: Failed to open trace file " ~ $opts.filepath;
        return 1;
    }

    my $tracker = Sigil::Flow::Tracker.new;

    while $driver.next-packet() -> $raw-pkt {
        my $pkt = Sigil::Core::Dissector::dissect-packet($raw-pkt);
        $tracker.process($pkt, $pkt.timestamp);
    }

    $driver.close();

    put "=== ACTIVE & COMPLETED CONVERSATION FLOWS ===";
    for $tracker.active-sessions -> $session {
        put $session.summary;
    }

    return 0;
}

# Subcommand: stats
method run-stats(Sigil::CLI::Options $opts --> Int) {
    if $opts.filepath eq "" {
        note "Error: No trace file specified. Use -r <trace.pcap>";
        return 1;
    }

    my $driver = Sigil::Capture::Offline.new(:filepath($opts.filepath));
    unless $driver.open() {
        note "Error: Failed to open trace file " ~ $opts.filepath;
        return 1;
    }

    my $collector = Sigil::Stats::Collector.new;

    while $driver.next-packet() -> $raw-pkt {
        my $pkt = Sigil::Core::Dissector::dissect-packet($raw-pkt);
        $collector.record($pkt, $pkt.timestamp);
    }

    $driver.close();
    print $collector.report ~ "\n";
    return 0;
}

# Subcommand: entropy
method run-entropy(Sigil::CLI::Options $opts --> Int) {
    if $opts.filepath eq "" {
        note "Error: No trace file specified. Use -r <trace.pcap>";
        return 1;
    }

    my $driver = Sigil::Capture::Offline.new(:filepath($opts.filepath));
    unless $driver.open() {
        note "Error: Failed to open trace file " ~ $opts.filepath;
        return 1;
    }

    put "=== PAYLOAD SHANNON ENTROPY AUDIT ===";
    put sprintf("%-6s  %-8s  %-10s  %-28s  %s", "Pkt #", "Proto", "Entropy", "Classification", "Payload Size");
    put "-" x 75;

    while $driver.next-packet() -> $raw-pkt {
        my $pkt = Sigil::Core::Dissector::dissect-packet($raw-pkt);
        my $payload = $pkt.payload;
        if $payload.elems > 0 {
            my $ent = Sigil::Stats::Entropy::shannon-entropy($payload);
            my $cls = Sigil::Stats::Entropy::classify-randomness($ent);
            my $proto = $pkt.highest-layer.defined ?? $pkt.highest-layer.name !! "RAW";
            put sprintf("#%-5d  %-8s  %6.3f bit  %-28s  %d bytes",
                $pkt.packet-id, $proto, $ent, $cls, $payload.elems);
        }
    }

    $driver.close();
    return 0;
}

# Subcommand: pcapng
method run-pcapng(Sigil::CLI::Options $opts --> Int) {
    if $opts.filepath eq "" {
        note "Error: No trace file specified. Use -r <trace.pcapng>";
        return 1;
    }

    my $parser = Sigil::PCAP::PCAPNG.open-file($opts.filepath);
    put "=== PCAPNG STRUCTURE & ENHANCED PACKET BLOCKS ===";

    my $cnt = 0;
    while $parser.read-next-packet() -> $pkt {
        put sprintf("EPB #%-5d %10.6f  Interface: %-8s  Wire: %-5d bytes  Captured: %-5d bytes",
            $pkt.packet-id, $pkt.timestamp, $pkt.interface, $pkt.wire-length, $pkt.capture-length);
        $cnt++;
        if $opts.packet-limit > 0 && $cnt >= $opts.packet-limit {
            last;
        }
    }

    put sprintf("Total Enhanced Packet Blocks parsed: %d", $cnt);
    return 0;
}

# Subcommand: filter
method run-filter(Sigil::CLI::Options $opts --> Int) {
    if $opts.filter-expr eq "" {
        note "Error: No filter expression provided. Use -f <expr>";
        return 1;
    }

    try {
        my $fn = Sigil::Filter::Engine::compile-filter($opts.filter-expr);
        put "Filter expression compiled successfully into AST and evaluator closure:";
        put "  Expression: " ~ $opts.filter-expr;
        return 0;
    }
    note "Filter compilation failed for: " ~ $opts.filter-expr;
    return 1;
}
