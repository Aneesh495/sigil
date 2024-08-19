# Sigil::Stats::Counter - Protocol, volume, and packet rate metrics
#
# Aggregates packet and byte counters across protocols, calculates bandwidth rates,
# and tracks dissection error frequencies.

unit class Sigil::Stats::Counter;

use Sigil::Types;
use Sigil::Core::Packet;

has Int $.total-packets = 0;
has Int $.total-bytes = 0;

# Protocol breakdown counters
has %!protocol-packets;                     # Str proto => Int count
has %!protocol-bytes;                       # Str proto => Int bytes

# Status outcome counters
has %!status-counts;                        # Str status => Int count

# Rate calculation window
has Num $.start-time = 0e0;
has Num $.last-time = 0e0;

# Record a processed packet
method record(Sigil::Core::Packet $pkt, Num $timestamp = 0e0) {
    my $ts = $timestamp > 0e0 ?? $timestamp !! now.Num;
    if $!start-time == 0e0 {
        $!start-time = $ts;
    }
    $!last-time = $ts;

    $!total-packets++;
    my $bytes = $pkt.length;
    $!total-bytes += $bytes;

    # Record protocols in packet stack
    for $pkt.layers -> $layer {
        my $pname = $layer.name;
        %!protocol-packets{$pname} = (%!protocol-packets{$pname} // 0) + 1;
        %!protocol-bytes{$pname} = (%!protocol-bytes{$pname} // 0) + $layer.header-length + $layer.payload-length;
    }

    # Record dissection status
    my $st-key = $pkt.status.key;
    %!status-counts{$st-key} = (%!status-counts{$st-key} // 0) + 1;
}

# Packets per second across total capture duration
method pps(--> Num) {
    my $dur = $!last-time - $!start-time;
    return $dur > 0e0 ?? ($!total-packets / $dur) !! 0e0;
}

# Megabits per second bandwidth
method mbps(--> Num) {
    my $dur = $!last-time - $!start-time;
    return $dur > 0e0 ?? (($!total-bytes * 8e0) / ($dur * 1000000e0)) !! 0e0;
}

# Protocol packet count
method proto-packets(Str $proto --> Int) {
    return %!protocol-packets{$proto} // 0;
}

# Protocol bytes count
method proto-bytes(Str $proto --> Int) {
    return %!protocol-bytes{$proto} // 0;
}

# Protocol percentage of total packets
method proto-percentage(Str $proto --> Num) {
    return $!total-packets > 0 ?? ((%!protocol-packets{$proto} // 0) * 100e0 / $!total-packets) !! 0e0;
}

# All recorded protocol names sorted by packet count descending
method top-protocols(--> List) {
    return %!protocol-packets.sort({ -$_.value }).map(*.key).list;
}

# Status count
method status-count(Str $status --> Int) {
    return %!status-counts{$status} // 0;
}

# Formatted summary string
method summary(--> Str) {
    my @lines;
    @lines.push(sprintf("Total Packets: %d | Total Bytes: %d (%.2f MB)", $!total-packets, $!total-bytes, $!total-bytes / 1048576e0));
    @lines.push(sprintf("Rate: %.2f pps | Bandwidth: %.3f Mbps", self.pps(), self.mbps()));
    @lines.push("Protocols:");
    for self.top-protocols() -> $p {
        @lines.push(sprintf("  %-12s %8d pkts (%5.1f%%) | %10d bytes",
            $p,
            %!protocol-packets{$p},
            self.proto-percentage($p),
            %!protocol-bytes{$p} // 0
        ));
    }
    return @lines.join("\n");
}
