# Sigil::Core::Dissector - Recursive protocol stack dissection pipeline
#
# Traverses encapsulated protocol layers from data link (L2) through application (L7),
# performing dynamic dissector lookups, heuristic probing, and telemetry accounting.

unit class Sigil::Core::Dissector;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Registry;
use Sigil::Core::Error;

# Protocol dissector imports
use Sigil::Grammar::Protocol::Ethernet;
use Sigil::Grammar::Protocol::ARP;
use Sigil::Grammar::Protocol::VLAN;
use Sigil::Grammar::Protocol::IPv4;
use Sigil::Grammar::Protocol::IPv6;
use Sigil::Grammar::Protocol::ICMPv4;
use Sigil::Grammar::Protocol::ICMPv6;
use Sigil::Grammar::Protocol::UDP;
use Sigil::Grammar::Protocol::TCP;
use Sigil::Grammar::Protocol::DNS;
use Sigil::Grammar::Protocol::DHCP;
use Sigil::Grammar::Protocol::NTP;
use Sigil::Grammar::Protocol::HTTP;
use Sigil::Grammar::Protocol::TLS;
use Sigil::Grammar::Protocol::WebSocket;
use Sigil::Grammar::Protocol::MQTT;
use Sigil::Grammar::Protocol::Redis;
use Sigil::Grammar::Protocol::BGP;
use Sigil::Grammar::Protocol::SSH;
use Sigil::Grammar::Protocol::Syslog;

has Int $.max-depth = 16;
has Int $.packets-processed = 0;
has Int $.bytes-processed = 0;
has Int $.errors-encountered = 0;
has %!protocol-counters;

my Sigil::Core::Registry $registry;

submethod TWEAK() {
    $registry = Sigil::Core::Registry.instance;
    self.init-default-registrations();
}

# Configure default protocol bindings in registry
method init-default-registrations() {
    # Link layer DLTs
    $registry.register-linktype(1, Sigil::Grammar::Protocol::Ethernet.new);

    # EtherTypes under Ethernet
    $registry.register-ethertype(0x0800, Sigil::Grammar::Protocol::IPv4.new);
    $registry.register-ethertype(0x86DD, Sigil::Grammar::Protocol::IPv6.new);
    $registry.register-ethertype(0x0806, Sigil::Grammar::Protocol::ARP.new);
    $registry.register-ethertype(0x8100, Sigil::Grammar::Protocol::VLAN.new);
    $registry.register-ethertype(0x88A8, Sigil::Grammar::Protocol::VLAN.new);

    # IP Protocols under IPv4 / IPv6
    $registry.register-ipproto(1,  Sigil::Grammar::Protocol::ICMPv4.new);
    $registry.register-ipproto(6,  Sigil::Grammar::Protocol::TCP.new);
    $registry.register-ipproto(17, Sigil::Grammar::Protocol::UDP.new);
    $registry.register-ipproto(58, Sigil::Grammar::Protocol::ICMPv6.new);

    # UDP Application ports
    $registry.register-udp-port(53,  Sigil::Grammar::Protocol::DNS.new);
    $registry.register-udp-port(67,  Sigil::Grammar::Protocol::DHCP.new);
    $registry.register-udp-port(68,  Sigil::Grammar::Protocol::DHCP.new);
    $registry.register-udp-port(123, Sigil::Grammar::Protocol::NTP.new);
    $registry.register-udp-port(514, Sigil::Grammar::Protocol::Syslog.new);

    # TCP Application ports
    $registry.register-tcp-port(80,   Sigil::Grammar::Protocol::HTTP.new);
    $registry.register-tcp-port(8080, Sigil::Grammar::Protocol::HTTP.new);
    $registry.register-tcp-port(443,  Sigil::Grammar::Protocol::TLS.new);
    $registry.register-tcp-port(8443, Sigil::Grammar::Protocol::TLS.new);
    $registry.register-tcp-port(6379, Sigil::Grammar::Protocol::Redis.new);
    $registry.register-tcp-port(179,  Sigil::Grammar::Protocol::BGP.new);
    $registry.register-tcp-port(22,   Sigil::Grammar::Protocol::SSH.new);
    $registry.register-tcp-port(1883, Sigil::Grammar::Protocol::MQTT.new);
    $registry.register-tcp-port(8883, Sigil::Grammar::Protocol::TLS.new);

    # Heuristic probes for payload detection
    $registry.register-heuristic(sub (Buf $p, Str $t --> Bool) {
        return False if $p.elems < 4;
        # HTTP Methods
        my $hdr = $p.subbuf(0, min(10, $p.elems)).decode('ascii', :replacement('?'));
        return ($hdr ~~ /^ ('GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'HTTP/') \s/);
    }, Sigil::Grammar::Protocol::HTTP.new);

    $registry.register-heuristic(sub (Buf $p, Str $t --> Bool) {
        # TLS Record: ContentType 20..24 and Version 0x0301..0x0304
        return False if $p.elems < 5;
        my $ct = $p[0];
        my $ver = ($p[1] +< 8) +| $p[2];
        return (20 <= $ct <= 24) && (0x0300 <= $ver <= 0x0304);
    }, Sigil::Grammar::Protocol::TLS.new);

    $registry.register-heuristic(sub (Buf $p, Str $t --> Bool) {
        # SSH banner starts with "SSH-"
        return False if $p.elems < 4;
        return ($p[0] == 0x53 && $p[1] == 0x53 && $p[2] == 0x48 && $p[3] == 0x2D);
    }, Sigil::Grammar::Protocol::SSH.new);
}

# Main dissection entrypoint: transforms raw frame into fully decoded Packet object
method dissect-packet(
    Buf $raw-bytes,
    Int :$linktype = 1,
    Int :$packet-id = 0,
    Num :$timestamp = 0e0,
    Int :$wire-length = $raw-bytes.elems,
    Int :$capture-length = $raw-bytes.elems,
    Str :$interface = "unknown",
    PacketDirection :$direction = DIR_UNKNOWN
    --> Sigil::Core::Packet
) {
    $!packets-processed++;
    $!bytes-processed += $raw-bytes.elems;

    my $packet = Sigil::Core::Packet.new(
        :raw($raw-bytes),
        :$packet-id,
        :$timestamp,
        :$wire-length,
        :$capture-length,
        :$interface,
        :$direction
    );

    # Identify initial link-layer dissector
    my $current-dissector = $registry.find-by-linktype($linktype);
    if !$current-dissector.defined {
        $!errors-encountered++;
        return $packet;
    }

    my $current-offset = 0;
    my $current-payload = $raw-bytes;
    my $depth = 0;
    my Sigil::Core::Layer $prev-layer = Nil;

    while $current-dissector.defined && $depth < $!max-depth && $current-payload.elems > 0 {
        $depth++;
        my Sigil::Core::Layer $layer;

        try {
            $layer = $current-dissector.dissect($raw-bytes, :offset($current-offset));
            CATCH {
                default {
                    $!errors-encountered++;
                    last;
                }
            }
        }

        last unless $layer.defined;

        # Record protocol telemetry
        %!protocol-counters{$layer.name}++;

        # Link parent/child relations
        if $prev-layer.defined {
            # Linked sequentially
        }

        $packet.push-layer($layer);
        $prev-layer = $layer;

        # Update offsets for inner payload
        $current-offset += $layer.header-length;
        $current-payload = $layer.raw-payload;

        # Determine next dissector based on layer metadata
        my $next-selector = $layer.next-protocol;
        my $next-dissector = Nil;

        if $layer.name eq "Ethernet" || $layer.name eq "VLAN" {
            $next-dissector = $registry.find-by-ethertype($next-selector.Int) if $next-selector.defined;
        } elsif $layer.name eq "IPv4" || $layer.name eq "IPv6" {
            $next-dissector = $registry.find-by-ipproto($next-selector.Int) if $next-selector.defined;
        } elsif $layer.name eq "TCP" {
            # Try port routing first, then heuristic probe on payload
            $next-dissector = $registry.find-by-tcp-port($next-selector.Int) if $next-selector.defined;
            if !$next-dissector.defined && $current-payload.elems > 0 {
                $next-dissector = $registry.find-by-heuristic($current-payload, 'TCP');
            }
        } elsif $layer.name eq "UDP" {
            $next-dissector = $registry.find-by-udp-port($next-selector.Int) if $next-selector.defined;
            if !$next-dissector.defined && $current-payload.elems > 0 {
                $next-dissector = $registry.find-by-heuristic($current-payload, 'UDP');
            }
        }

        $current-dissector = $next-dissector;
    }

    return $packet;
}

# Telemetry stats
method stats(--> Hash) {
    return {
        packets_processed  => $!packets-processed,
        bytes_processed    => $!bytes-processed,
        errors_encountered => $!errors-encountered,
        protocols          => %!protocol-counters
    };
}
