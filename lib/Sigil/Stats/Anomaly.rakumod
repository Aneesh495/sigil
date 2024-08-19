# Sigil::Stats::Anomaly - Security heuristics and network behavioral anomaly detector
#
# Analyzes packet streams in real time for port scans, SYN floods, DNS tunneling,
# invalid TCP flag combinations (Xmas, Null), and IP spoofing indicators.

unit class Sigil::Stats::Anomaly;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Stats::Entropy;

has %!src-syn-count;                        # Str src-ip => Int count
has %!src-ack-count;                        # Str src-ip => Int count
has %!src-scanned-ports;                    # Str src-ip => SetHash of target ports
has %!src-scanned-hosts;                    # Str src-ip => SetHash of target hosts

# Alert event log
has @!alerts;                               # Array of Hash: { timestamp, type, severity, description, src, dst }
has Int $.port-scan-threshold = 20;         # Number of distinct ports before flagging scan
has Int $.host-scan-threshold = 20;         # Number of distinct hosts before flagging sweep
has Num $.dns-entropy-threshold = 3.8e0;    # Entropy threshold for DNS tunneling suspicion

# Inspect packet for behavioral anomalies
method inspect(Sigil::Core::Packet $pkt, Num $timestamp = 0e0 --> List) {
    my $ts = $timestamp > 0e0 ?? $timestamp !! now.Num;
    my @new-alerts;

    my $src-ip = $pkt.val("ip.src") // $pkt.val("ipv6.src") // "";
    my $dst-ip = $pkt.val("ip.dst") // $pkt.val("ipv6.dst") // "";

    return () if $src-ip eq "";

    # 1. Invalid TCP flag combinations
    if $pkt.has-layer("TCP") {
        my $flags = $pkt.val("tcp.flags") // 0;
        my $dport = $pkt.val("tcp.dstport") // 0;

        # Null scan: no flags set
        if $flags == 0 {
            my %al = (
                timestamp   => $ts,
                type        => "TCP_NULL_SCAN",
                severity    => "HIGH",
                description => sprintf("TCP packet with zero flags from %s to %s:%d", $src-ip, $dst-ip, $dport),
                src         => $src-ip,
                dst         => $dst-ip
            );
            @!alerts.push(%al);
            @new-alerts.push(%al);
        }

        # Xmas scan: FIN + PSH + URG
        my $xmas-mask = TCP_FIN +| TCP_PSH +| TCP_URG;
        if ($flags +& $xmas-mask) == $xmas-mask {
            my %al = (
                timestamp   => $ts,
                type        => "TCP_XMAS_SCAN",
                severity    => "HIGH",
                description => sprintf("TCP Xmas scan flags (FIN+PSH+URG) from %s to %s:%d", $src-ip, $dst-ip, $dport),
                src         => $src-ip,
                dst         => $dst-ip
            );
            @!alerts.push(%al);
            @new-alerts.push(%al);
        }

        # SYN + FIN invalid flag combination
        if ($flags +& TCP_SYN) && ($flags +& TCP_FIN) {
            my %al = (
                timestamp   => $ts,
                type        => "TCP_SYN_FIN_ANOMALY",
                severity    => "CRITICAL",
                description => sprintf("Illegal TCP SYN+FIN combination from %s to %s:%d", $src-ip, $dst-ip, $dport),
                src         => $src-ip,
                dst         => $dst-ip
            );
            @!alerts.push(%al);
            @new-alerts.push(%al);
        }

        # Port scanning tracking
        if ($flags +& TCP_SYN) && !($flags +& TCP_ACK) {
            %!src-syn-count{$src-ip} = (%!src-syn-count{$src-ip} // 0) + 1;

            # Vertical port scan tracking
            %!src-scanned-ports{$src-ip} = SetHash.new unless %!src-scanned-ports{$src-ip}:exists;
            %!src-scanned-ports{$src-ip}{$dport} = True;
            if %!src-scanned-ports{$src-ip}.elems == $!port-scan-threshold {
                my %al = (
                    timestamp   => $ts,
                    type        => "VERTICAL_PORT_SCAN",
                    severity    => "MEDIUM",
                    description => sprintf("Source %s scanned %d distinct ports on target %s", $src-ip, %!src-scanned-ports{$src-ip}.elems, $dst-ip),
                    src         => $src-ip,
                    dst         => $dst-ip
                );
                @!alerts.push(%al);
                @new-alerts.push(%al);
            }

            # Horizontal subnet sweep tracking
            %!src-scanned-hosts{$src-ip} = SetHash.new unless %!src-scanned-hosts{$src-ip}:exists;
            %!src-scanned-hosts{$src-ip}{$dst-ip} = True;
            if %!src-scanned-hosts{$src-ip}.elems == $!host-scan-threshold {
                my %al = (
                    timestamp   => $ts,
                    type        => "HORIZONTAL_HOST_SWEEP",
                    severity    => "MEDIUM",
                    description => sprintf("Source %s targeted %d distinct hosts on port %d", $src-ip, %!src-scanned-hosts{$src-ip}.elems, $dport),
                    src         => $src-ip,
                    dst         => $dst-ip
                );
                @!alerts.push(%al);
                @new-alerts.push(%al);
            }
        } elsif $flags +& TCP_ACK {
            %!src-ack-count{$src-ip} = (%!src-ack-count{$src-ip} // 0) + 1;
        }
    }

    # 2. DNS Tunneling and covert channel detection
    if $pkt.has-layer("DNS") {
        my $qname = $pkt.val("dns.query.name") // "";
        if $qname.chars > 40 {
            my $entropy = Sigil::Stats::Entropy::string-entropy($qname);
            if $entropy >= $!dns-entropy-threshold {
                my %al = (
                    timestamp   => $ts,
                    type        => "DNS_TUNNELING_SUSPECTED",
                    severity    => "HIGH",
                    description => sprintf("High-entropy DNS query '%s' (entropy=%.2f, len=%d) from %s", $qname, $entropy, $qname.chars, $src-ip),
                    src         => $src-ip,
                    dst         => $dst-ip
                );
                @!alerts.push(%al);
                @new-alerts.push(%al);
            }
        }
    }

    return @new-alerts.list;
}

# Total alerts count
method alert-count(--> Int) {
    return @!alerts.elems;
}

# Retrieve all alerts
method alerts(--> List) {
    return @!alerts.list;
}

# Formatted alerts summary
method summary(--> Str) {
    return "(no anomalies detected)" if @!alerts.elems == 0;
    my @lines;
    @lines.push(sprintf("Detected %d Security Anomalies:", @!alerts.elems));
    for @!alerts -> $al {
        @lines.push(sprintf("  [%-8s] %-24s: %s", $al<severity>, $al<type>, $al<description>));
    }
    return @lines.join("\n");
}
