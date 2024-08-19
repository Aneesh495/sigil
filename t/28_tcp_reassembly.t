use v6.d;
use Test;
use Sigil::Types;
use Sigil::Flow::TCPStream;

plan 15;

# 1. In-order sequential reassembly
{
    my $stream = Sigil::Flow::TCPStream.new;
    $stream.init-syn(1000);
    is $stream.next-seq, 1001, "Initial SYN sets next-seq to ISN + 1";

    my $chunk1 = Buf.new("GET /inde".encode('ascii'));
    my $out1 = $stream.add-segment(1001, $chunk1);
    is $out1.decode('ascii'), "GET /inde", "In-order segment 1 delivered immediately";
    is $stream.next-seq, 1010, "next-seq advanced by chunk length";

    my $chunk2 = Buf.new("x.html HTTP/1.1\r\n".encode('ascii'));
    my $out2 = $stream.add-segment(1010, $chunk2);
    is $out2.decode('ascii'), "x.html HTTP/1.1\r\n", "In-order segment 2 delivered immediately";
    is $stream.bytes-delivered, 26, "Total bytes delivered matches sum of chunks";
}

# 2. Out-of-order segment buffering and hole filling
{
    my $stream = Sigil::Flow::TCPStream.new;
    $stream.init-syn(2000);

    # Deliver segment 2 first (seq 2011..2020) - 10 bytes
    my $seg2 = Buf.new("WORLD!1234".encode('ascii'));
    my $out2 = $stream.add-segment(2011, $seg2);
    is $out2.elems, 0, "Out-of-order segment 2 is buffered, returning empty buffer";
    is $stream.pending-chunks, 1, "Pending chunks count is 1";
    is $stream.out-of-order-segments, 1, "Out-of-order segments counter incremented";

    # Deliver segment 1 (seq 2001..2010) - 10 bytes: fills hole and flushes both!
    my $seg1 = Buf.new("HELLO_TCP_".encode('ascii'));
    my $out1 = $stream.add-segment(2001, $seg1);
    is $out1.decode('ascii'), "HELLO_TCP_WORLD!1234", "Delivering hole segment flushed both seg1 and seg2 contiguously";
    is $stream.pending-chunks, 0, "Pending queue drained to 0";
    is $stream.next-seq, 2021, "next-seq advanced to end of seg2";
}

# 3. Duplicate retransmission handling
{
    my $stream = Sigil::Flow::TCPStream.new;
    $stream.init-syn(3000);

    my $seg1 = Buf.new("DATA_ONE".encode('ascii'));
    my $out1 = $stream.add-segment(3001, $seg1);
    is $out1.decode('ascii'), "DATA_ONE", "Segment 1 delivered";

    # Duplicate retransmission of segment 1
    my $dup1 = $stream.add-segment(3001, $seg1);
    is $dup1.elems, 0, "Exact duplicate segment yields empty buffer";
    is $stream.retransmitted-bytes, 8, "Retransmitted bytes tracked accurately";
}

# 4. Partial overlap handling
{
    my $stream = Sigil::Flow::TCPStream.new;
    $stream.init-syn(4000);

    my $seg1 = Buf.new("12345".encode('ascii')); # seq 4001..4005, next = 4006
    $stream.add-segment(4001, $seg1);

    # Overlapping segment: starts at 4004 (2 bytes overlap: '45'), has new bytes '6789'
    my $overlap = Buf.new("456789".encode('ascii'));
    my $out = $stream.add-segment(4004, $overlap);
    is $out.decode('ascii'), "6789", "Overlapping segment trims redundant prefix and delivers suffix";
}

done-testing;
