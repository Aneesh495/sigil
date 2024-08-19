# Sigil::Flow::Key - 5-tuple flow key and bidirectional session normalization
#
# Encapsulates (Protocol, Source IP, Destination IP, Source Port, Destination Port)
# with canonical direction normalization for unified bidirectional flow tracking.

unit class Sigil::Flow::Key;

use Sigil::Types;
use Sigil::Core::Packet;

has Str $.proto is required;        # "TCP", "UDP", "ICMP", etc.
has Str $.src-ip is required;
has Str $.dst-ip is required;
has Int $.src-port = 0;
has Int $.dst-port = 0;

# Canonical canonical-key string representation independent of packet direction
has Str $.canonical-id;

submethod TWEAK() {
    $!canonical-id = self.compute-canonical-id();
}

# Factory from parsed Packet
method from-packet(Sigil::Core::Packet $pkt --> Sigil::Flow::Key) {
    my $proto = "RAW";
    my $src-ip = "0.0.0.0";
    my $dst-ip = "0.0.0.0";
    my $src-port = 0;
    my $dst-port = 0;

    if $pkt.has-layer("TCP") {
        $proto = "TCP";
        $src-port = $pkt.val("tcp.srcport") // 0;
        $dst-port = $pkt.val("tcp.dstport") // 0;
    } elsif $pkt.has-layer("UDP") {
        $proto = "UDP";
        $src-port = $pkt.val("udp.srcport") // 0;
        $dst-port = $pkt.val("udp.dstport") // 0;
    } elsif $pkt.has-layer("ICMPv4") {
        $proto = "ICMPv4";
    } elsif $pkt.has-layer("ICMPv6") {
        $proto = "ICMPv6";
    }

    if $pkt.has-layer("IPv4") {
        $src-ip = $pkt.val("ip.src") // "0.0.0.0";
        $dst-ip = $pkt.val("ip.dst") // "0.0.0.0";
    } elsif $pkt.has-layer("IPv6") {
        $src-ip = $pkt.val("ipv6.src") // "::";
        $dst-ip = $pkt.val("ipv6.dst") // "::";
    }

    return self.new(
        :$proto,
        :$src-ip,
        :$dst-ip,
        :$src-port,
        :$dst-port
    );
}

# Compute unique bidirectional session identifier by lexicographically ordering endpoints
method compute-canonical-id(--> Str) {
    my $ep1 = sprintf("%s:%d", $!src-ip, $!src-port);
    my $ep2 = sprintf("%s:%d", $!dst-ip, $!dst-port);

    my ($first, $second) = ($ep1 le $ep2) ?? ($ep1, $ep2) !! ($ep2, $ep1);
    return sprintf("%s %s <-> %s", $!proto, $first, $second);
}

# Determine if a packet is aligned with forward initiator direction
method is-forward(Str $pkt-src-ip, Int $pkt-src-port --> Bool) {
    return ($pkt-src-ip eq $!src-ip) && ($pkt-src-port == $!src-port);
}

# Inverse key for opposite direction
method reverse(--> Sigil::Flow::Key) {
    return Sigil::Flow::Key.new(
        :proto($!proto),
        :src-ip($!dst-ip),
        :dst-ip($!src-ip),
        :src-port($!dst-port),
        :dst-port($!src-port)
    );
}

method Str(--> Str) {
    return sprintf("%s %s:%d -> %s:%d", $!proto, $!src-ip, $!src-port, $!dst-ip, $!dst-port);
}
