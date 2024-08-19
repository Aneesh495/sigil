# Sigil::Stats::Entropy - Shannon entropy and payload randomness analysis
#
# Computes information entropy across packet payloads and sliding byte windows
# to detect encryption, compression, obfuscated code, and DNS exfiltration tunnels.

unit class Sigil::Stats::Entropy;

use Sigil::Types;

# Calculate Shannon entropy of a byte buffer (returns bits per symbol: 0.0 to 8.0)
our sub shannon-entropy(Buf $data --> Num) is export {
    my $len = $data.elems;
    return 0e0 if $len == 0;

    # Count byte frequencies across 256 possible octet values
    my @freq = 0 xx 256;
    for $data.list -> $b {
        @freq[$b]++;
    }

    my $entropy = 0e0;
    my $inv-len = 1e0 / $len;

    for 0..255 -> $i {
        my $count = @freq[$i];
        if $count > 0 {
            my $p = $count * $inv-len;
            $entropy -= $p * ($p.log / 2e0.log);
        }
    }

    return $entropy;
}

# Calculate Shannon entropy of an ASCII/UTF-8 string (e.g. DNS subdomains, HTTP headers)
our sub string-entropy(Str $text --> Num) is export {
    return 0e0 if $text.chars == 0;
    my $buf = Buf.new($text.encode('utf-8'));
    return shannon-entropy($buf);
}

# Sliding-window entropy scan across a large payload buffer
# Returns array of (offset, window_entropy)
our sub sliding-window-entropy(Buf $data, Int $window-size = 64, Int $step = 16 --> List) is export {
    my @points;
    my $len = $data.elems;
    return @points if $len < $window-size;

    my $offset = 0;
    while $offset + $window-size <= $len {
        my $slice = $data.subbuf($offset, $window-size);
        my $ent = shannon-entropy($slice);
        @points.push({ offset => $offset, entropy => $ent });
        $offset += $step;
    }

    return @points.list;
}

# Chi-squared goodness-of-fit statistic against uniform distribution (256 bins)
our sub chi-squared(Buf $data --> Num) is export {
    my $len = $data.elems;
    return 0e0 if $len < 256;

    my @freq = 0 xx 256;
    for $data.list -> $b {
        @freq[$b]++;
    }

    my $expected = $len / 256e0;
    my $chi2 = 0e0;

    for 0..255 -> $i {
        my $diff = @freq[$i] - $expected;
        $chi2 += ($diff * $diff) / $expected;
    }

    return $chi2;
}

# Classification heuristic
our sub classify-randomness(Num $entropy --> Str) is export {
    if $entropy < 3.0e0 {
        return "plain-text-or-sparse";
    } elsif $entropy < 6.0e0 {
        return "structured-binary-or-code";
    } elsif $entropy < 7.2e0 {
        return "compressed-or-packed";
    } else {
        return "encrypted-or-high-entropy";
    }
}
