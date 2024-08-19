# Sigil::Flow::TCPStream - Out-of-order TCP segment reassembly and hole tracking
#
# Reassembles sliding-window TCP byte streams, fills sequence holes, trims overlapping
# duplicate retransmissions, and flushes contiguous application payload chunks.

unit class Sigil::Flow::TCPStream;

use Sigil::Types;

has Int $.initial-seq = 0;                  # Initial Sequence Number (ISN)
has Int $.next-seq = 0;                     # Next expected contiguous byte sequence number
has Bool $.has-syn = False;                 # Whether SYN segment has been seen
has Bool $.has-fin = False;                 # Whether FIN segment has been seen

has @!segments;                             # Sorted list of out-of-order chunks: { seq => Int, data => Buf }
has Int $.bytes-delivered = 0;              # Total contiguous payload bytes delivered to application layer
has Int $.retransmitted-bytes = 0;          # Duplicate/retransmitted bytes detected
has Int $.out-of-order-segments = 0;        # Segments received out of sequence
has Int $.max-queue-size = 1048576;         # 1 MB maximum queue memory per stream direction

# Set initial sequence number from SYN segment
method init-syn(Int $isn) {
    $!initial-seq = $isn;
    $!next-seq = ($isn + 1) +& 0xFFFFFFFF;
    $!has-syn = True;
}

# Ingest TCP segment; returns contiguous bytes reassembled from this and queued segments
method add-segment(Int $seq, Buf $payload --> Buf) {
    return Buf.new if $payload.elems == 0;

    # If stream was not initialized with SYN, initialize on first seen data segment
    if !$!has-syn && $!next-seq == 0 {
        $!initial-seq = $seq;
        $!next-seq = $seq;
    }

    my @flushed-chunks;

    # Case 1: In-order contiguous segment
    if $seq == $!next-seq {
        @flushed-chunks.push($payload);
        $!next-seq = ($!next-seq + $payload.elems) +& 0xFFFFFFFF;
        $!bytes-delivered += $payload.elems;

        # Drain any out-of-order segments queued that now become contiguous
        self.drain-queue(@flushed-chunks);
    }
    # Case 2: Segment starts before expected next-seq (Retransmission or partial overlap)
    elsif $seq < $!next-seq {
        my $overlap = $!next-seq - $seq;
        if $overlap < $payload.elems {
            # Partial overlap: slice new unread suffix
            my $new-bytes = $payload.subbuf($overlap);
            $!retransmitted-bytes += $overlap;
            @flushed-chunks.push($new-bytes);
            $!next-seq = ($!next-seq + $new-bytes.elems) +& 0xFFFFFFFF;
            $!bytes-delivered += $new-bytes.elems;
            self.drain-queue(@flushed-chunks);
        } else {
            # Full duplicate retransmission
            $!retransmitted-bytes += $payload.elems;
        }
    }
    # Case 3: Out-of-order segment (hole in sequence)
    else {
        $!out-of-order-segments++;
        self.enqueue-segment($seq, $payload);
    }

    # Concatenate all flushed chunks into single contiguous buffer
    if @flushed-chunks.elems == 0 {
        return Buf.new;
    } elsif @flushed-chunks.elems == 1 {
        return @flushed-chunks[0];
    } else {
        my @all-bytes;
        for @flushed-chunks -> $chunk {
            for $chunk.list -> $b {
                @all-bytes.push($b);
            }
        }
        return Buf.new(@all-bytes);
    }
}

# Insert segment into sorted out-of-order queue
method enqueue-segment(Int $seq, Buf $data) {
    # Check queue memory limit
    my $curr-queued = @!segments.map(*<data>.elems).sum;
    if $curr-queued + $data.elems > $!max-queue-size {
        return; # Drop segment if queue limit exceeded
    }

    my $inserted = False;
    for 0 ..^ @!segments.elems -> $i {
        if $seq < @!segments[$i]<seq> {
            @!segments.splice($i, 0, { seq => $seq, data => $data });
            $inserted = True;
            last;
        } elsif $seq == @!segments[$i]<seq> {
            # Duplicate queued segment
            $inserted = True;
            last;
        }
    }
    @!segments.push({ seq => $seq, data => $data }) unless $inserted;
}

# Drain queued segments that have become contiguous with next-seq
method drain-queue(@flushed-chunks) {
    while @!segments.elems > 0 {
        my $candidate = @!segments[0];
        my $cand-seq = $candidate<seq>;
        my $cand-data = $candidate<data>;

        if $cand-seq == $!next-seq {
            @!segments.shift;
            @flushed-chunks.push($cand-data);
            $!next-seq = ($!next-seq + $cand-data.elems) +& 0xFFFFFFFF;
            $!bytes-delivered += $cand-data.elems;
        } elsif $cand-seq < $!next-seq {
            # Queued segment partially or fully consumed
            @!segments.shift;
            my $overlap = $!next-seq - $cand-seq;
            if $overlap < $cand-data.elems {
                my $new-bytes = $cand-data.subbuf($overlap);
                @flushed-chunks.push($new-bytes);
                $!next-seq = ($!next-seq + $new-bytes.elems) +& 0xFFFFFFFF;
                $!bytes-delivered += $new-bytes.elems;
            }
        } else {
            # Hole still exists
            last;
        }
    }
}

# Number of currently pending out-of-order chunks
method pending-chunks(--> Int) {
    return @!segments.elems;
}
