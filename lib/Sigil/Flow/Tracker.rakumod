# Sigil::Flow::Tracker - Central session table, flow aging, and stream reassembly
#
# Aggregates L3/L4 packets into bidirectional sessions, tracks active connections,
# reassembles byte streams, and garbage-collects idle/terminated sessions.

unit class Sigil::Flow::Tracker;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Flow::Key;
use Sigil::Flow::Session;

has %!sessions;                             # Str canonical-id => Sigil::Flow::Session
has Num $.tcp-idle-timeout = 300e0;         # 5 minutes idle timeout for TCP
has Num $.udp-idle-timeout = 60e0;          # 1 minute idle timeout for UDP
has Num $.tcp-closed-timeout = 10e0;        # 10 seconds timeout for terminated sessions

has Int $.total-sessions-created = 0;
has Int $.total-sessions-expired = 0;

# Callbacks
has &.on-session-create is rw;                    # sub (Sigil::Flow::Session)
has &.on-payload-reassembled is rw;               # sub (Sigil::Flow::Session, Bool $is-c2s, Buf $payload)
has &.on-session-close is rw;                     # sub (Sigil::Flow::Session, Str $reason)

# Process packet through flow tracking engine
method process(Sigil::Core::Packet $pkt, Num $timestamp = 0e0 --> Sigil::Flow::Session) {
    my $key = Sigil::Flow::Key.from-packet($pkt);
    my $id = $key.canonical-id;

    my $session;
    if %!sessions{$id}:exists {
        $session = %!sessions{$id};
    } else {
        $session = Sigil::Flow::Session.new(:key($key), :start-time($timestamp > 0e0 ?? $timestamp !! now.Num));
        %!sessions{$id} = $session;
        $!total-sessions-created++;
        if &!on-session-create.defined {
            &!on-session-create($session);
        }
    }

    # Ingest packet into session
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
    my $is-c2s = $key.is-forward($pkt-src-ip, $pkt-src-port);

    my $flushed = $session.update($pkt, $timestamp);

    # Trigger payload callback if contiguous bytes were reassembled
    if $flushed.elems > 0 && &!on-payload-reassembled.defined {
        &!on-payload-reassembled($session, $is-c2s, $flushed);
    }

    # Trigger session close callback if session just completed
    if $session.is-closed && &!on-session-close.defined {
        &!on-session-close($session, $session.close-reason);
    }

    return $session;
}

# Scan and purge aged-out or terminated sessions
method purge-idle(Num $current-time = 0e0 --> Int) {
    my $now-ts = $current-time > 0e0 ?? $current-time !! now.Num;
    my @to-remove;

    for %!sessions.kv -> $id, $session {
        my $idle = $now-ts - $session.last-time;
        my $is-tcp = $session.key.proto eq "TCP";

        if $session.is-closed {
            if $idle >= $!tcp-closed-timeout {
                @to-remove.push($id);
            }
        } elsif $is-tcp {
            if $idle >= $!tcp-idle-timeout {
                $session.close-reason = "timeout";
                @to-remove.push($id);
            }
        } else {
            if $idle >= $!udp-idle-timeout {
                $session.close-reason = "timeout";
                @to-remove.push($id);
            }
        }
    }

    for @to-remove -> $id {
        my $sess = %!sessions{$id};
        if &!on-session-close.defined && !$sess.is-closed {
            &!on-session-close($sess, "timeout");
        }
        %!sessions{$id}:delete;
        $!total-sessions-expired++;
    }

    return @to-remove.elems;
}

# Retrieve session by canonical ID
method get(Str $id --> Sigil::Flow::Session) {
    return %!sessions{$id} // Sigil::Flow::Session;
}

# Active session count
method active-count(--> Int) {
    return %!sessions.elems;
}

# All active sessions list
method active-sessions(--> List) {
    return %!sessions.values.list;
}

# Clear all tracked sessions
method clear() {
    %!sessions = ();
}
