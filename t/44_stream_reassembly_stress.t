use v6.d;
use Test;
use Sigil::Types;
use Sigil::Flow::TCPStream;

plan 14;

# 1. Reverse order segment ingestion (10 segments in reverse order: 10 down to 1)
{
    my $stream = Sigil::Flow::TCPStream.new;
    $stream.init-syn(1000);

    my @chunks;
    for 1..10 -> $i {
        @chunks.push(Buf.new("CHUNK_{$i}_".encode('ascii')));
    }

    # Calculate sequence numbers for each chunk
    my @seqs;
    my $curr = 1001;
    for @chunks -> $c {
        @seqs.push($curr);
        $curr += $c.elems;
    }

    # Feed segments in completely reversed order (chunks 9 down to 1)
    for (1..9).reverse -> $i {
        my $flushed = $stream.add-segment(@seqs[$i], @chunks[$i]);
        is $flushed.elems, 0, "Out-of-order reversed segment $i is held in pending queue";
    }
    is $stream.pending-chunks, 9, "All 9 out-of-order segments are buffered";

    # Now deliver segment 0 (the missing head)
    my $full-delivered = $stream.add-segment(@seqs[0], @chunks[0]);
    ok $full-delivered.elems > 0, "Delivering missing head segment flushes entire queued chain";
    is $stream.pending-chunks, 0, "Pending queue completely drained";

    # Verify concatenated payload
    my $expected = (1..10).map({ "CHUNK_{$_}_" }).join("");
    is $full-delivered.decode('ascii'), $expected, "Entire byte stream reassembled in exact sequential order";
    is $stream.bytes-delivered, $expected.encode('ascii').elems, "Delivered byte count matches reconstructed message length";
}

done-testing;
