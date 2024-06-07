# Sigil::Core::Checksum - Network protocol checksum and cyclic redundancy calculation
#
# Implements RFC 1071 Internet checksums, IPv4/IPv6 pseudo-header checksums,
# IEEE 802.3 Ethernet CRC-32, and Adler-32 integrity algorithms.

unit package Sigil::Core::Checksum;

use Sigil::Types;

# Precomputed table for IEEE 802.3 CRC-32 polynomial 0xEDB88320 (initialized at compile time)
my @crc32-table = BEGIN {
    my @tbl;
    for 0..255 -> $i {
        my uint32 $c = $i;
        for 0..7 {
            if $c +& 1 {
                $c = 0xEDB88320 +^ ($c +> 1);
            } else {
                $c = $c +> 1;
            }
        }
        @tbl[$i] = $c;
    }
    @tbl;
};

# RFC 1071 16-bit one's complement Internet checksum calculation
our sub internet-checksum(Buf $data, Int $offset = 0, Int $length = $data.elems - $offset --> Int) is export {
    my $len = min($length, $data.elems - $offset);
    return 0 if $len <= 0;

    my uint32 $sum = 0;
    my $idx = $offset;
    my $remaining = $len;

    # Accumulate 16-bit big-endian words
    while $remaining >= 2 {
        my $word = ($data[$idx] +< 8) +| $data[$idx + 1];
        $sum += $word;
        $idx += 2;
        $remaining -= 2;
    }

    # Handle odd byte trailing at end of buffer
    if $remaining == 1 {
        my $word = $data[$idx] +< 8;
        $sum += $word;
    }

    # Fold 32-bit sum into 16 bits (end-around carry)
    while ($sum +> 16) > 0 {
        $sum = ($sum +& 0xFFFF) + ($sum +> 16);
    }

    # One's complement inversion
    return (+^$sum) +& 0xFFFF;
}

# Verify validity of Internet checksum over header containing computed checksum field
our sub verify-internet-checksum(Buf $data, Int $offset = 0, Int $length = $data.elems - $offset --> Bool) is export {
    my $len = min($length, $data.elems - $offset);
    return False if $len <= 0;

    my uint32 $sum = 0;
    my $idx = $offset;
    my $remaining = $len;

    while $remaining >= 2 {
        my $word = ($data[$idx] +< 8) +| $data[$idx + 1];
        $sum += $word;
        $idx += 2;
        $remaining -= 2;
    }

    if $remaining == 1 {
        my $word = $data[$idx] +< 8;
        $sum += $word;
    }

    while ($sum +> 16) > 0 {
        $sum = ($sum +& 0xFFFF) + ($sum +> 16);
    }

    # Valid if all ones (0xFFFF) or zero
    return $sum == 0xFFFF || $sum == 0;
}

# IPv4 pseudo-header partial accumulator for TCP and UDP
our sub ipv4-pseudo-header-sum(Str $src-ip, Str $dst-ip, Int $proto, Int $length --> Int) is export {
    my @src = $src-ip.split('.').map(*.Int);
    my @dst = $dst-ip.split('.').map(*.Int);

    my uint32 $sum = 0;
    $sum += (@src[0] +< 8) +| @src[1];
    $sum += (@src[2] +< 8) +| @src[3];
    $sum += (@dst[0] +< 8) +| @dst[1];
    $sum += (@dst[2] +< 8) +| @dst[3];
    $sum += $proto;
    $sum += $length;

    return $sum;
}

# Complete TCP checksum calculation over IPv4 transport
our sub tcp-checksum-ipv4(Str $src-ip, Str $dst-ip, Buf $tcp-segment --> Int) is export {
    my uint32 $sum = ipv4-pseudo-header-sum($src-ip, $dst-ip, 6, $tcp-segment.elems);

    my $idx = 0;
    my $remaining = $tcp-segment.elems;

    while $remaining >= 2 {
        my $word = ($tcp-segment[$idx] +< 8) +| $tcp-segment[$idx + 1];
        $sum += $word;
        $idx += 2;
        $remaining -= 2;
    }

    if $remaining == 1 {
        $sum += ($tcp-segment[$idx] +< 8);
    }

    while ($sum +> 16) > 0 {
        $sum = ($sum +& 0xFFFF) + ($sum +> 16);
    }

    return (+^$sum) +& 0xFFFF;
}

# Complete UDP checksum calculation over IPv4 transport
our sub udp-checksum-ipv4(Str $src-ip, Str $dst-ip, Buf $udp-datagram --> Int) is export {
    my uint32 $sum = ipv4-pseudo-header-sum($src-ip, $dst-ip, 17, $udp-datagram.elems);

    my $idx = 0;
    my $remaining = $udp-datagram.elems;

    while $remaining >= 2 {
        my $word = ($udp-datagram[$idx] +< 8) +| $udp-datagram[$idx + 1];
        $sum += $word;
        $idx += 2;
        $remaining -= 2;
    }

    if $remaining == 1 {
        $sum += ($udp-datagram[$idx] +< 8);
    }

    while ($sum +> 16) > 0 {
        $sum = ($sum +& 0xFFFF) + ($sum +> 16);
    }

    my $res = (+^$sum) +& 0xFFFF;
    # RFC 768: If computed checksum is zero, transmit 0xFFFF
    return $res == 0 ?? 0xFFFF !! $res;
}

# IEEE 802.3 Frame Check Sequence CRC-32
our sub crc32(Buf $data, Int $offset = 0, Int $length = $data.elems - $offset --> Int) is export {
    my $len = min($length, $data.elems - $offset);
    return 0 if $len <= 0;

    my uint32 $crc = 0xFFFFFFFF;
    my $end = $offset + $len;

    for $offset ..^ $end -> $i {
        my $b = $data[$i];
        my $tbl-idx = ($crc +^ $b) +& 0xFF;
        $crc = @crc32-table[$tbl-idx] +^ ($crc +> 8);
    }

    return ($crc +^ 0xFFFFFFFF) +& 0xFFFFFFFF;
}

# Adler-32 algorithm (RFC 1950)
our sub adler32(Buf $data, Int $offset = 0, Int $length = $data.elems - $offset --> Int) is export {
    my $len = min($length, $data.elems - $offset);
    return 1 if $len <= 0;

    my uint32 $a = 1;
    my uint32 $b = 0;
    my $mod = 65521;
    my $end = $offset + $len;

    for $offset ..^ $end -> $i {
        $a = ($a + $data[$i]) % $mod;
        $b = ($b + $a) % $mod;
    }

    return (($b +< 16) +| $a) +& 0xFFFFFFFF;
}
