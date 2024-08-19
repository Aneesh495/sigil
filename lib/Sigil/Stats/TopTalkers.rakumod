# Sigil::Stats::TopTalkers - Space-Saving stream algorithm for heavy hitter estimation
#
# Tracks high-volume endpoints and flow pairs in O(k) bounded memory with provable
# maximum estimation error bounds (Metwally, Agrawal, El Abbadi algorithm).

unit class Sigil::Stats::TopTalkers;

has Int $.capacity = 100;                   # Maximum distinct keys retained in memory
has %!counts;                               # Str key => Int estimated-count
has %!errors;                               # Str key => Int max-estimation-error
has Int $.total-events = 0;

submethod BUILD(Int :$!capacity = 100) {}

# Observe an event key with an increment weight (e.g. 1 packet, or N bytes)
method observe(Str $key, Int $weight = 1) {
    return if $key eq "" || $weight <= 0;
    $!total-events += $weight;

    if %!counts{$key}:exists {
        # Key already monitored: exact increment
        %!counts{$key} += $weight;
    } elsif %!counts.elems < $!capacity {
        # Space available: allocate new exact entry
        %!counts{$key} = $weight;
        %!errors{$key} = 0;
    } else {
        # Table full: find key with minimum count, replace it
        my $min-key = "";
        my $min-val = Inf;

        for %!counts.kv -> $k, $v {
            if $v < $min-val {
                $min-val = $v;
                $min-key = $k;
            }
        }

        # Evict min-key and assign new key count = min-val + weight, error = min-val
        %!counts{$min-key}:delete;
        my $prev-err = %!errors{$min-key}:delete // 0;

        %!counts{$key} = $min-val.Int + $weight;
        %!errors{$key} = $min-val.Int;
    }
}

# Retrieve top-N entries sorted by count descending
method top(Int $n = 10 --> List) {
    my @ranked = %!counts.sort({ -$_.value });
    my $limit = (@ranked.elems < $n) ?? @ranked.elems !! $n;

    my @results;
    for 0 ..^ $limit -> $i {
        my $k = @ranked[$i].key;
        my $c = @ranked[$i].value;
        my $err = %!errors{$k} // 0;
        my $pct = ($!total-events > 0) ?? ($c * 100e0 / $!total-events) !! 0e0;
        @results.push({
            key        => $k,
            count      => $c,
            max_error  => $err,
            percentage => $pct
        });
    }
    return @results.list;
}

# Formatted tabular view
method summary(Int $n = 10 --> Str) {
    my @items = self.top($n);
    return "(no events recorded)" if @items.elems == 0;

    my @lines;
    @lines.push(sprintf("  %-30s | %10s | %9s | %6s", "Key / Endpoint", "Count", "Max Error", "%"));
    @lines.push("  " ~ ("-" x 30) ~ "-+-" ~ ("-" x 10) ~ "-+-" ~ ("-" x 9) ~ "-+-------");

    for @items -> $item {
        @lines.push(sprintf(
            "  %-30s | %10d | %9d | %5.1f%%",
            $item<key>,
            $item<count>,
            $item<max_error>,
            $item<percentage>
        ));
    }

    return @lines.join("\n");
}
