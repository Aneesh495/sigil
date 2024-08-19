# Sigil::Stats::Histogram - Log-linear distribution analysis and percentile estimation
#
# Bins continuous measurements (packet sizes, latencies, inter-arrival intervals)
# into log-linear buckets with percentiles (p50, p90, p99) and ASCII visual charts.

unit class Sigil::Stats::Histogram;

has Str $.name = "latency";
has @!bucket-bounds;                        # Upper limits of buckets
has @!bucket-counts;                        # Frequency count per bucket
has Int $.count = 0;
has Num $.sum = 0e0;
has Num $.min-val = Inf;
has Num $.max-val = -Inf;

# Reservoir sample for accurate non-parametric percentile estimation
has @!sample;
has Int $.sample-capacity = 4096;

submethod BUILD(Str :$!name = "latency", :@bounds) {
    if @bounds.elems > 0 {
        @!bucket-bounds = @bounds.sort;
    } else {
        # Default packet size boundaries (Ethernet standard MTU spectrum)
        @!bucket-bounds = [64, 128, 256, 512, 1024, 1518, 9000];
    }
    @!bucket-counts = [0 xx (@!bucket-bounds.elems + 1)];
}

# Record a numeric observation
method record(Real $val) {
    my $v = $val.Num;
    $!count++;
    $!sum += $v;
    $!min-val = $v if $v < $!min-val;
    $!max-val = $v if $v > $!max-val;

    # Locate bucket
    my $placed = False;
    for 0 ..^ @!bucket-bounds.elems -> $i {
        if $v <= @!bucket-bounds[$i] {
            @!bucket-counts[$i]++;
            $placed = True;
            last;
        }
    }
    @!bucket-counts[*-1]++ unless $placed;

    # Reservoir sampling (Algorithm R)
    if @!sample.elems < $!sample-capacity {
        @!sample.push($v);
    } else {
        my $j = (0 ..^ $!count).pick;
        if $j < $!sample-capacity {
            @!sample[$j] = $v;
        }
    }
}

# Arithmetic mean
method mean(--> Num) {
    return $!count > 0 ?? ($!sum / $!count) !! 0e0;
}

# Minimum observed value
method min(--> Num) {
    return $!count > 0 ?? $!min-val !! 0e0;
}

# Maximum observed value
method max(--> Num) {
    return $!count > 0 ?? $!max-val !! 0e0;
}

# Percentile calculation (0.0 to 1.0, e.g. 0.50 for median, 0.99 for p99)
method percentile(Real $p --> Num) {
    return 0e0 if @!sample.elems == 0;
    my @sorted = @!sample.sort;
    my $idx = ($p.Num * (@sorted.elems - 1)).round.Int;
    $idx = 0 if $idx < 0;
    $idx = @sorted.elems - 1 if $idx >= @sorted.elems;
    return @sorted[$idx];
}

# Median (50th percentile)
method p50(--> Num) { return self.percentile(0.50e0); }

# 90th percentile
method p90(--> Num) { return self.percentile(0.90e0); }

# 99th percentile
method p99(--> Num) { return self.percentile(0.99e0); }

# ASCII horizontal bar distribution chart
method ascii-chart(Int $bar-width = 40 --> Str) {
    return "(empty)" if $!count == 0;
    my $max-c = @!bucket-counts.max;
    return "(zero counts)" if $max-c == 0;

    my @lines;
    for 0 .. @!bucket-bounds.elems -> $i {
        my $label = ($i == 0)
            ?? sprintf("<= %-5d", @!bucket-bounds[0])
            !! ($i == @!bucket-bounds.elems)
                ?? sprintf(">  %-5d", @!bucket-bounds[*-1])
                !! sprintf("%4d..%-4d", @!bucket-bounds[$i - 1] + 1, @!bucket-bounds[$i]);

        my $c = @!bucket-counts[$i];
        my $len = (($c / $max-c) * $bar-width).round.Int;
        my $bar = "#" x $len;
        my $pct = ($c / $!count) * 100e0;

        @lines.push(sprintf("  %-11s | %-*s | %6d (%5.1f%%)", $label, $bar-width, $bar, $c, $pct));
    }

    return @lines.join("\n");
}

# Formatted statistical summary
method summary(--> Str) {
    return sprintf(
        "Histogram '%s' (N=%d): min=%.2f, mean=%.2f, p50=%.2f, p90=%.2f, p99=%.2f, max=%.2f",
        $!name, $!count, self.min(), self.mean(), self.p50(), self.p90(), self.p99(), self.max()
    );
}
