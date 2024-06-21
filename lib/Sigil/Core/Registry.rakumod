# Sigil::Core::Registry - Dynamic dissector registration and protocol routing table
#
# Routes protocol payloads to specialized dissectors based on link layer types,
# EtherTypes, IP protocol numbers, TCP/UDP ports, and heuristic probes.

unit class Sigil::Core::Registry;

use Sigil::Types;

has %!linktype-table;    # DLT (e.g. 1 for Ethernet) -> Dissector Class
has %!ethertype-table;   # EtherType (e.g. 0x0800)   -> Dissector Class
has %!ipproto-table;     # IP Protocol (e.g. 6)      -> Dissector Class
has %!tcp-port-table;    # TCP Port (e.g. 443)       -> Dissector Class
has %!udp-port-table;    # UDP Port (e.g. 53)        -> Dissector Class
has @!heuristics;        # Array of Pair: (sub(Buf, Str --> Bool) => Dissector Class)

my Sigil::Core::Registry $instance;

# Singleton accessor
method instance(--> Sigil::Core::Registry) {
    $instance //= Sigil::Core::Registry.new();
    return $instance;
}

# Register dissector for data link type (DLT)
method register-linktype(Int $dlt, $dissector) {
    %!linktype-table{$dlt} = $dissector;
}

# Lookup dissector for DLT
method find-by-linktype(Int $dlt) {
    return %!linktype-table{$dlt} // Nil;
}

# Register dissector for EtherType code
method register-ethertype(Int $ethertype, $dissector) {
    %!ethertype-table{$ethertype} = $dissector;
}

# Lookup dissector for EtherType
method find-by-ethertype(Int $ethertype) {
    return %!ethertype-table{$ethertype} // Nil;
}

# Register dissector for IP Protocol number
method register-ipproto(Int $proto, $dissector) {
    %!ipproto-table{$proto} = $dissector;
}

# Lookup dissector for IP Protocol number
method find-by-ipproto(Int $proto) {
    return %!ipproto-table{$proto} // Nil;
}

# Register dissector for TCP destination or source port
method register-tcp-port(Int $port, $dissector) {
    %!tcp-port-table{$port} = $dissector;
}

# Lookup dissector for TCP port
method find-by-tcp-port(Int $port) {
    return %!tcp-port-table{$port} // Nil;
}

# Register dissector for UDP destination or source port
method register-udp-port(Int $port, $dissector) {
    %!udp-port-table{$port} = $dissector;
}

# Lookup dissector for UDP port
method find-by-udp-port(Int $port) {
    return %!udp-port-table{$port} // Nil;
}

# Register heuristic pattern checker
method register-heuristic(&probe, $dissector) {
    @!heuristics.push((&probe => $dissector));
}

# Evaluate registered heuristics against payload
method find-by-heuristic(Buf $payload, Str $transport --> Any) {
    for @!heuristics -> $pair {
        my $probe = $pair.key;
        my $dissector = $pair.value;
        if $probe($payload, $transport) {
            return $dissector;
        }
    }
    return Nil;
}

# Dump all registered routes for debugging
method dump-registry(--> Hash) {
    return {
        linktypes  => %!linktype-table.keys.sort,
        ethertypes => %!ethertype-table.keys.sort,
        ipprotos   => %!ipproto-table.keys.sort,
        tcp_ports  => %!tcp-port-table.keys.sort,
        udp_ports  => %!udp-port-table.keys.sort,
        heuristics => @!heuristics.elems
    };
}
