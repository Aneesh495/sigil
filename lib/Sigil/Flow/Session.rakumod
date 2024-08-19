# Sigil::Flow::Session - Bidirectional conversation metrics and stream state
#
# Tracks two-way communication between two endpoints, maintaining directional
# counters, sequence state, RTT estimates, and application protocol classification.

unit class Sigil::Flow::Session;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Flow::Key;
use Sigil::Flow::TCPState;
use Sigil::Flow::TCPStream;

has Sigil::Flow::Key $.key is required;
has Num $.start-time = 0e0;
has Num $.last-time = 0e0;

# Bidirectional metrics
has Int $.c2s-packets = 0;
has Int $.c2s-bytes = 0;
has Int $.s2c-packets = 0;
has Int $.s2c-bytes = 0;

# RTT Tracking (Round Trip Time in seconds)
has Num $.syn-time = 0e0;
has Num $.syn-ack-time = 0e0;
has Num $.handshake-rtt = 0e0;
has Num $.smoothed-rtt = 0e0;

# Protocol and Application Layer
has Str $.app-protocol = "unknown";
has Str $.close-reason is rw = "active"; # "fin", "rst", "timeout", "active"

# State and Reassembly engines (for TCP)
has Sigil::Flow::TCPState $.tcp-state;
has Sigil::Flow::TCPStream $.c2s-stream;
has Sigil::Flow::TCPStream $.s2c-stream;

submethod TWEAK() {
    if $!key.proto eq "TCP" {
        $!tcp-state = Sigil::Flow::TCPState.new;
        $!c2s-stream = Sigil::Flow::TCPStream.new;
        $!s2c-stream = Sigil::Flow::TCPStream.new;
    }
}

# Update session with a new packet
method update(Sigil::Core::Packet $pkt, Num $timestamp = 0e0 --> Buf) {
    my $ts = $timestamp > 0e0 ?? $timestamp !! (now.Num);
    if $!start-time == 0e0 {
        $!start-time = $ts;
    }
    $!last-time = $ts;

    # Determine direction based on canonical initiator key
    my $pkt-src-ip = "";
    my $pkt-src-port = 0;

    if $pkt.has-layer("IPv4") {
        $pkt-src-ip = $pkt.val("ip.src") // "";
    } elsif $pkt.has-layer("IPv6") {
        $pkt-src-ip = $pkt.val("ipv6.src") // "";
    }

    if $pkt.has-layer("TCP") {
        $pkt-src-port = $pkt.val("tcp.srcport") // 0;
    } elsif $pkt.has-layer("UDP") {
        $pkt-src-port = $pkt.val("udp.srcport") // 0;
    }

    my $is-c2s = $!key.is-forward($pkt-src-ip, $pkt-src-port);
    my $pkt-len = $pkt.length;

    if $is-c2s {
        $!c2s-packets++;
        $!c2s-bytes += $pkt-len;
    } else {
        $!s2c-packets++;
        $!s2c-bytes += $pkt-len;
    }

    # Inspect L7 application protocol
    if $!app-protocol eq "unknown" {
        for <HTTP TLS DNS DHCP NTP WebSocket MQTT Redis BGP SSH Syslog> -> $proto {
            if $pkt.has-layer($proto) {
                $!app-protocol = $proto;
                last;
            }
        }
    }

    # If TCP, handle state transitions, RTT calculation, and stream reassembly
    my $flushed-payload = Buf.new;
    if $pkt.has-layer("TCP") && $!tcp-state.defined {
        my $flags = $pkt.val("tcp.flags") // 0;
        my $seq = $pkt.val("tcp.seq") // 0;
        my $payload = $pkt.payload;

        $!tcp-state.process-flags($flags, $is-c2s);

        # Measure handshake RTT
        my $syn = ($flags +& TCP_SYN) != 0;
        my $ack = ($flags +& TCP_ACK) != 0;
        if $is-c2s && $syn && !$ack {
            $!syn-time = $ts;
            $!c2s-stream.init-syn($seq);
        } elsif !$is-c2s && $syn && $ack {
            $!syn-ack-time = $ts;
            $!s2c-stream.init-syn($seq);
            if $!syn-time > 0e0 {
                $!handshake-rtt = $ts - $!syn-time;
                $!smoothed-rtt = $!handshake-rtt;
            }
        }

        # Deliver payload into corresponding directional stream
        if $payload.elems > 0 {
            if $is-c2s {
                $flushed-payload = $!c2s-stream.add-segment($seq, $payload);
            } else {
                $flushed-payload = $!s2c-stream.add-segment($seq, $payload);
            }
        }

        # Track close reason
        if ($flags +& TCP_RST) != 0 {
            $!close-reason = "rst";
        } elsif ($flags +& TCP_FIN) != 0 {
            $!close-reason = "fin";
        }
    }

    return $flushed-payload;
}

# Duration of session in seconds
method duration(--> Num) {
    return ($!last-time >= $!start-time) ?? ($!last-time - $!start-time) !! 0e0;
}

# Total bidirectional packets
method total-packets(--> Int) {
    return $!c2s-packets + $!s2c-packets;
}

# Total bidirectional bytes
method total-bytes(--> Int) {
    return $!c2s-bytes + $!s2c-bytes;
}

# Is session closed or inactive
method is-closed(--> Bool) {
    if $!tcp-state.defined {
        return $!tcp-state.is-closed || $!tcp-state.is-reset;
    }
    return $!close-reason ne "active";
}

# Formatted one-line summary
method summary(--> Str) {
    my $state-str = $!tcp-state.defined ?? $!tcp-state.summary() !! "UDP";
    return sprintf(
        '%-6s %s [%s] Pkts: %d(c2s) / %d(s2c) | Bytes: %d(c2s) / %d(s2c) | Dur: %.3fs | %s',
        $!key.proto,
        $!key.canonical-id,
        $state-str,
        $!c2s-packets,
        $!s2c-packets,
        $!c2s-bytes,
        $!s2c-bytes,
        self.duration(),
        $!app-protocol
    );
}
