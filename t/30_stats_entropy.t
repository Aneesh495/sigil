use v6.d;
use Test;
use Sigil::Stats::Entropy;

plan 10;

# 1. Zero entropy for homogeneous byte buffer
{
    my $zeros = Buf.new(0 xx 256);
    my $ent0 = Sigil::Stats::Entropy::shannon-entropy($zeros);
    is-approx $ent0, 0e0, 1e-4, "All identical zero bytes yield 0.0 Shannon entropy";

    my $ones = Buf.new(0xFF xx 512);
    my $ent1 = Sigil::Stats::Entropy::shannon-entropy($ones);
    is-approx $ent1, 0e0, 1e-4, "All identical 0xFF bytes yield 0.0 Shannon entropy";
}

# 2. Maximum entropy for perfectly uniform 256-byte distribution (8.0 bits)
{
    my $uniform = Buf.new(0..255);
    my $ent_max = Sigil::Stats::Entropy::shannon-entropy($uniform);
    is-approx $ent_max, 8e0, 1e-4, "Uniform distribution over 256 symbols yields exactly 8.0 bits of entropy";
}

# 3. String entropy for English text vs random hex
{
    my $text = "The quick brown fox jumps over the lazy dog";
    my $ent_text = Sigil::Stats::Entropy::string-entropy($text);
    ok 3.0e0 < $ent_text < 4.8e0, "English sentence entropy is within expected linguistic range (3.0 to 4.8)";

    my $repetitive = "AAAAABBBBBCCCCCDDDDDEEEEE";
    my $ent_rep = Sigil::Stats::Entropy::string-entropy($repetitive);
    ok $ent_text > $ent_rep, "Natural language exhibits higher entropy than repetitive string";
}

# 4. Sliding-window entropy scan
{
    # Construct buffer: 64 zero bytes followed by 64 uniform bytes
    my @raw;
    @raw.append(0 xx 64);
    @raw.append((0..255).pick xx 64);
    my $buf = Buf.new(@raw);

    my @points = Sigil::Stats::Entropy::sliding-window-entropy($buf, 32, 16);
    ok @points.elems >= 5, "Sliding window produces correct number of samples";
    is-approx @points[0]<entropy>, 0e0, 1e-4, "First window over all zeroes has 0.0 entropy";
}

# 5. Chi-squared goodness-of-fit
{
    # 2560 bytes with exactly 10 of each byte 0..255
    my @uniform_bytes;
    for 1..10 {
        @uniform_bytes.append(0..255);
    }
    my $chi2 = Sigil::Stats::Entropy::chi-squared(Buf.new(@uniform_bytes));
    is-approx $chi2, 0e0, 1e-4, "Uniform distribution yields chi-squared value of 0.0";
}

# 6. Randomness classification
{
    is Sigil::Stats::Entropy::classify-randomness(1.5e0), "plain-text-or-sparse", "Low entropy classified as plain text";
    is Sigil::Stats::Entropy::classify-randomness(7.8e0), "encrypted-or-high-entropy", "High entropy classified as encrypted";
}

done-testing;
