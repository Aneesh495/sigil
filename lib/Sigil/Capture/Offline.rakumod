# Sigil::Capture::Offline - Offline trace file replay driver with rate pacing
#
# Slurps or streams classic PCAP and PCAPNG files with configurable time dilation
# (unthrottled line-rate, real-time 1x replay, or accelerated benchmarks).

unit class Sigil::Capture::Offline;

use Sigil::Core::Packet;
use Sigil::Capture::Driver;
use Sigil::PCAP::Reader;
use Sigil::PCAP::PCAPNG;

also does Sigil::Capture::Driver;

has Str $.filepath is required;
has Num $.rate-multiplier = 0e0;            # 0.0 = unthrottled, 1.0 = real-time, >1.0 = fast-forward
has Any $!reader;                           # Reader or PCAPNG instance
has Num $!first-packet-ts = 0e0;
has Num $!replay-start-ts = 0e0;
has Int $.packets-read = 0;
has Int $.bytes-read = 0;
has Bool $.is-open = False;

# Open capture trace file
method open(--> Bool) {
    die "Trace file '$!filepath' not found" unless $!filepath.IO.e;

    # Sniff first 4 bytes to check if PCAPNG or classic PCAP
    my $fh = $!filepath.IO.open(:r, :bin);
    my $magic-bytes = $fh.read(4);
    $fh.close;

    if $magic-bytes.elems >= 4 {
        my $b0 = $magic-bytes[0];
        my $b1 = $magic-bytes[1];
        my $b2 = $magic-bytes[2];
        my $b3 = $magic-bytes[3];

        # PCAPNG starts with 0x0A 0x0D 0x0D 0x0A
        if $b0 == 0x0A && $b1 == 0x0D && $b2 == 0x0D && $b3 == 0x0A {
            $!reader = Sigil::PCAP::PCAPNG.open-file($!filepath);
        } else {
            $!reader = Sigil::PCAP::Reader.open-file($!filepath);
        }
        $!is-open = True;
        $!replay-start-ts = now.Num;
        return True;
    }

    return False;
}

# Fetch next packet with optional rate pacing
method next-packet(--> Sigil::Core::Packet) {
    return Nil unless $!is-open;

    my $pkt;
    if $!reader ~~ Sigil::PCAP::PCAPNG {
        $pkt = $!reader.read-next-packet();
    } else {
        $pkt = $!reader.read-next();
    }

    return Nil unless $pkt.defined;

    $!packets-read++;
    $!bytes-read += $pkt.capture-length;

    # Rate pacing simulation if requested
    if $!rate-multiplier > 0e0 {
        if $!first-packet-ts == 0e0 {
            $!first-packet-ts = $pkt.timestamp;
            $!replay-start-ts = now.Num;
        } else {
            my $packet-delta = ($pkt.timestamp - $!first-packet-ts) / $!rate-multiplier;
            my $actual-delta = now.Num - $!replay-start-ts;
            my $delay = $packet-delta - $actual-delta;
            if $delay > 0.0005e0 && $delay < 5e0 {
                sleep($delay);
            }
        }
    }

    return $pkt;
}

# Capture stats
method stats(--> Hash) {
    my $elapsed = now.Num - $!replay-start-ts;
    return {
        packets_read => $!packets-read,
        bytes_read   => $!bytes-read,
        elapsed_sec  => $elapsed,
        avg_pps      => ($elapsed > 0e0) ?? ($!packets-read / $elapsed) !! 0e0
    };
}

# Close trace file
method close() {
    $!is-open = False;
    $!reader = Nil;
}
