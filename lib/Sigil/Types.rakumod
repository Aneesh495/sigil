# Sigil::Types - Core type definitions, subsets, and protocol enumerations
#
# Provides domain-specific type constraints and protocol constants across
# the entire Sigil network telemetry and dissection subsystem.

unit package Sigil::Types;

# Link-layer EtherType identifiers (IEEE 802.3 / Ethernet II)
enum EtherType is export (
    ETHERTYPE_IPV4   => 0x0800,
    ETHERTYPE_ARP    => 0x0806,
    ETHERTYPE_WOL    => 0x0842,
    ETHERTYPE_RARP   => 0x8035,
    ETHERTYPE_VLAN   => 0x8100,
    ETHERTYPE_IPV6   => 0x86DD,
    ETHERTYPE_MPLS   => 0x8847,
    ETHERTYPE_QINQ   => 0x88A8,
    ETHERTYPE_LLDP   => 0x88CC,
    ETHERTYPE_MACSEC => 0x88E5
);

# Transport and network layer protocol numbers (IANA Assigned Internet Protocol Numbers)
enum IPProtocol is export (
    IPPROTO_HOPOPT   => 0,
    IPPROTO_ICMP     => 1,
    IPPROTO_IGMP     => 2,
    IPPROTO_GGP      => 3,
    IPPROTO_IPV4     => 4,
    IPPROTO_ST       => 5,
    IPPROTO_TCP      => 6,
    IPPROTO_CBT      => 7,
    IPPROTO_EGP      => 8,
    IPPROTO_IGP      => 9,
    IPPROTO_UDP      => 17,
    IPPROTO_RDP      => 27,
    IPPROTO_IPV6     => 41,
    IPPROTO_ROUTING  => 43,
    IPPROTO_FRAGMENT => 44,
    IPPROTO_RSVP     => 46,
    IPPROTO_GRE      => 47,
    IPPROTO_ESP      => 50,
    IPPROTO_AH       => 51,
    IPPROTO_ICMPV6   => 58,
    IPPROTO_NONE     => 59,
    IPPROTO_DSTOPTS  => 60,
    IPPROTO_OSPF     => 89,
    IPPROTO_PIM      => 103,
    IPPROTO_SCTP     => 132
);

# Transmission Control Protocol control flags (RFC 9293)
enum TCPFlag is export (
    TCP_FIN => 0x001,
    TCP_SYN => 0x002,
    TCP_RST => 0x004,
    TCP_PSH => 0x008,
    TCP_ACK => 0x010,
    TCP_URG => 0x020,
    TCP_ECE => 0x040,
    TCP_CWR => 0x080,
    TCP_NS  => 0x100
);

# Directionality of captured packet stream relative to monitored vantage point
enum PacketDirection is export (
    DIR_UNKNOWN  => 0,
    DIR_INBOUND  => 1,
    DIR_OUTBOUND => 2,
    DIR_INTERNAL => 3
);

# Status outcomes for protocol dissector pipeline
enum DissectionStatus is export (
    STATUS_OK                => 0,
    STATUS_TRUNCATED         => 1,
    STATUS_CHECKSUM_MISMATCH => 2,
    STATUS_MALFORMED         => 3,
    STATUS_UNSUPPORTED       => 4,
    STATUS_OUT_OF_BOUNDS     => 5
);

# TCP session state machine enumerations (RFC 793 / RFC 9293)
enum TCPState is export (
    TCP_STATE_LISTEN       => 1,
    TCP_STATE_SYN_SENT     => 2,
    TCP_STATE_SYN_RECEIVED => 3,
    TCP_STATE_ESTABLISHED  => 4,
    TCP_STATE_FIN_WAIT_1   => 5,
    TCP_STATE_FIN_WAIT_2   => 6,
    TCP_STATE_CLOSE_WAIT   => 7,
    TCP_STATE_CLOSING      => 8,
    TCP_STATE_LAST_ACK     => 9,
    TCP_STATE_TIME_WAIT    => 10,
    TCP_STATE_CLOSED       => 11
);

# Port number constraint (0 through 65535)
subset PortNumber of Int is export where 0 <= $_ <= 65535;

# Octet constraint (0 through 255)
subset Octet of Int is export where 0 <= $_ <= 255;

# 16-bit unsigned integer constraint
subset Word16 of Int is export where 0 <= $_ <= 0xFFFF;

# 32-bit unsigned integer constraint
subset Word32 of Int is export where 0 <= $_ <= 0xFFFFFFFF;

# Validated IEEE 802 48-bit MAC address string representation (xx:xx:xx:xx:xx:xx)
subset MACAddress of Str is export where /^
    (<[0..9a..fA..F]>**2) ** 6 % ':'
$/;

# Validated IPv4 dotted-decimal string representation
subset IPv4Str of Str is export where {
    if $_ ~~ /^ (\d**1..3) '.' (\d**1..3) '.' (\d**1..3) '.' (\d**1..3) $/ {
        $0.Int <= 255 && $1.Int <= 255 && $2.Int <= 255 && $3.Int <= 255;
    } else {
        False;
    }
};

# Validated IPv6 address representation
subset IPv6Str of Str is export where {
    $_ ~~ /^ [<[0..9a..fA..F]>**1..4] ** 1..8 % ':' $/ ||
    $_ ~~ /^ [<[0..9a..fA..F]>*] '::' [<[0..9a..fA..F]>*] $/;
};

# Helper function: Convert EtherType integer code to human readable name
sub ethertype-to-name(Int $val --> Str) is export {
    return do given $val {
        when 0x0800 { 'IPv4' }
        when 0x0806 { 'ARP' }
        when 0x8100 { '802.1Q VLAN' }
        when 0x86DD { 'IPv6' }
        when 0x8847 { 'MPLS' }
        when 0x88A8 { '802.1ad QinQ' }
        when 0x88CC { 'LLDP' }
        default     { sprintf("0x%04x", $val) }
    }
}

# Helper function: Convert IP protocol number to human readable name
sub ipproto-to-name(Int $val --> Str) is export {
    return do given $val {
        when 1   { 'ICMP' }
        when 2   { 'IGMP' }
        when 4   { 'IPv4-encap' }
        when 6   { 'TCP' }
        when 17  { 'UDP' }
        when 41  { 'IPv6-encap' }
        when 47  { 'GRE' }
        when 50  { 'ESP' }
        when 51  { 'AH' }
        when 58  { 'ICMPv6' }
        when 89  { 'OSPF' }
        when 132 { 'SCTP' }
        default  { sprintf("IP-PROTO-%d", $val) }
    }
}

# Helper function: Parse TCP flag bitfield into human readable string sequence
sub tcp-flags-to-str(Int $flags --> Str) is export {
    my @parts;
    @parts.push('FIN') if $flags +& 0x001;
    @parts.push('SYN') if $flags +& 0x002;
    @parts.push('RST') if $flags +& 0x004;
    @parts.push('PSH') if $flags +& 0x008;
    @parts.push('ACK') if $flags +& 0x010;
    @parts.push('URG') if $flags +& 0x020;
    @parts.push('ECE') if $flags +& 0x040;
    @parts.push('CWR') if $flags +& 0x080;
    @parts.push('NS')  if $flags +& 0x100;
    return @parts.join(',');
}
