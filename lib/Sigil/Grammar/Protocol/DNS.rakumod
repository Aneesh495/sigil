# Sigil::Grammar::Protocol::DNS - Domain Name System message dissector (RFC 1035)
#
# Implements full RFC 1035 DNS message parsing, recursive label decompression (0xC0 pointer
# following), Question sections, and Resource Record decoders (A, AAAA, CNAME, MX, TXT, PTR).

unit class Sigil::Grammar::Protocol::DNS;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing DNS message
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base DNS header requires 12 bytes
    if $buf.remaining < 12 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("DNS"),
            :display-name("Domain Name System (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("DNS message truncated: expected at least 12 bytes for header")
        );
    }

    my $start-offset = $buf.offset;
    my $tx-id = $buf.read-uint16-be();
    my $flags = $buf.read-uint16-be();

    my $qr     = ($flags +> 15) +& 0x01;
    my $opcode = ($flags +> 11) +& 0x0F;
    my $aa     = ($flags +> 10) +& 0x01;
    my $tc     = ($flags +> 9)  +& 0x01;
    my $rd     = ($flags +> 8)  +& 0x01;
    my $ra     = ($flags +> 7)  +& 0x01;
    my $z      = ($flags +> 6)  +& 0x01;
    my $ad     = ($flags +> 5)  +& 0x01;
    my $cd     = ($flags +> 4)  +& 0x01;
    my $rcode  = $flags +& 0x0F;

    my $qd-count = $buf.read-uint16-be();
    my $an-count = $buf.read-uint16-be();
    my $ns-count = $buf.read-uint16-be();
    my $ar-count = $buf.read-uint16-be();

    my %opcodes = (
        0 => "Standard Query",
        1 => "Inverse Query",
        2 => "Server Status",
        4 => "Notify",
        5 => "Update"
    );

    my %rcodes = (
        0 => "No Error",
        1 => "Format Error",
        2 => "Server Failure",
        3 => "Non-Existent Domain (NXDomain)",
        4 => "Not Implemented",
        5 => "Query Refused"
    );

    my %qtypes = (
        1   => "A",
        2   => "NS",
        5   => "CNAME",
        6   => "SOA",
        12  => "PTR",
        15  => "MX",
        16  => "TXT",
        28  => "AAAA",
        33  => "SRV",
        41  => "OPT",
        255 => "ANY"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::IntField.new(
        :name("Transaction ID"),
        :key("dns.id"),
        :offset-bytes(0),
        :length-bytes(2),
        :value($tx-id),
        :radix("hex"),
        :bit-width(16)
    ));

    $fl.add(Sigil::Core::FlagField.new(:name("Response (QR)"), :key("dns.flags.response"), :offset-bytes(2), :length-bytes(2), :mask(0x8000), :is-set($qr == 1)));
    $fl.add(Sigil::Core::EnumField.new(:name("Opcode"), :key("dns.flags.opcode"), :offset-bytes(2), :length-bytes(2), :value($opcode), :name-map(%opcodes)));
    $fl.add(Sigil::Core::FlagField.new(:name("Authoritative (AA)"), :key("dns.flags.authoritative"), :offset-bytes(2), :length-bytes(2), :mask(0x0400), :is-set($aa == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("Truncated (TC)"), :key("dns.flags.truncated"), :offset-bytes(2), :length-bytes(2), :mask(0x0200), :is-set($tc == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("Recursion Desired (RD)"), :key("dns.flags.recdesired"), :offset-bytes(2), :length-bytes(2), :mask(0x0100), :is-set($rd == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("Recursion Available (RA)"), :key("dns.flags.recavail"), :offset-bytes(2), :length-bytes(2), :mask(0x0080), :is-set($ra == 1)));
    $fl.add(Sigil::Core::EnumField.new(:name("Reply Code (RCODE)"), :key("dns.flags.rcode"), :offset-bytes(3), :length-bytes(1), :value($rcode), :name-map(%rcodes)));

    $fl.add(Sigil::Core::IntField.new(:name("Questions"), :key("dns.count.queries"), :offset-bytes(4), :length-bytes(2), :value($qd-count)));
    $fl.add(Sigil::Core::IntField.new(:name("Answer RRs"), :key("dns.count.answers"), :offset-bytes(6), :length-bytes(2), :value($an-count)));
    $fl.add(Sigil::Core::IntField.new(:name("Authority RRs"), :key("dns.count.auth_rr"), :offset-bytes(8), :length-bytes(2), :value($ns-count)));
    $fl.add(Sigil::Core::IntField.new(:name("Additional RRs"), :key("dns.count.add_rr"), :offset-bytes(10), :length-bytes(2), :value($ar-count)));

    # Helper sub for decoding DNS domain name with compression pointers
    my sub read-dns-name(Sigil::Core::Buffer $b, Buf $msg-raw, Int $msg-start --> Str) {
        my @labels;
        my $jumps = 0;
        my $max-jumps = 16; # Safeguard against circular pointer loops

        while $b.remaining > 0 {
            my $len = $b.read-uint8();
            last if $len == 0; # Null label signifies end of domain name

            if ($len +& 0xC0) == 0xC0 { # Pointer (0xC0XX)
                if $b.remaining < 1 {
                    last;
                }
                my $lo = $b.read-uint8();
                my $ptr-offset = (($len +& 0x3F) +< 8) +| $lo;
                if ++$jumps > $max-jumps || $ptr-offset >= $msg-raw.elems {
                    last; # Avoid loops or out-of-bounds
                }
                # Create auxiliary reader at pointed location
                my $ptr-buf = Sigil::Core::Buffer.new($msg-raw, :offset($msg-start + $ptr-offset));
                my $sub-name = read-dns-name($ptr-buf, $msg-raw, $msg-start);
                @labels.push($sub-name) if $sub-name ne "";
                last; # Pointer terminates local sequence
            } else {
                # Standard length-prefixed label
                if $b.remaining >= $len {
                    my $label-bytes = $b.read-bytes($len);
                    @labels.push($label-bytes.decode('ascii'));
                } else {
                    last;
                }
            }
        }

        return @labels.join('.');
    }

    # Parse Questions Section
    my @questions;
    for 0 ..^ $qd-count {
        last if $buf.at-eof;
        my $qname = read-dns-name($buf, $raw, $start-offset);
        if $buf.remaining >= 4 {
            my $qtype = $buf.read-uint16-be();
            my $qclass = $buf.read-uint16-be();
            @questions.push({ name => $qname, type => $qtype, class => $qclass });
            $fl.add(Sigil::Core::StringField.new(
                :name("Query Name"),
                :key("dns.qry.name"),
                :value($qname)
            ));
            $fl.add(Sigil::Core::EnumField.new(
                :name("Query Type"),
                :key("dns.qry.type"),
                :value($qtype),
                :name-map(%qtypes)
            ));
        }
    }

    # Parse Resource Record Sections (Answers, Authority, Additional)
    my sub parse-rr-section(Int $count, Str $section-name, Str $key-prefix) {
        my @rrs;
        for 0 ..^ $count {
            last if $buf.at-eof;
            my $rr-name = read-dns-name($buf, $raw, $start-offset);
            last if $buf.remaining < 10;

            my $rr-type = $buf.read-uint16-be();
            my $rr-class = $buf.read-uint16-be();
            my $ttl = $buf.read-uint32-be();
            my $rdlen = $buf.read-uint16-be();

            last if $buf.remaining < $rdlen;
            my $rdata-val = "";

            if $rr-type == 1 && $rdlen == 4 { # A record (IPv4)
                $rdata-val = $buf.read-ipv4();
            } elsif $rr-type == 28 && $rdlen == 16 { # AAAA record (IPv6)
                $rdata-val = $buf.read-ipv6();
            } elsif $rr-type == (2 | 5 | 12) { # NS, CNAME, PTR
                my $rr-buf = Sigil::Core::Buffer.new($buf.read-bytes($rdlen));
                $rdata-val = read-dns-name($rr-buf, $raw, $start-offset);
            } elsif $rr-type == 15 && $rdlen >= 3 { # MX
                my $pref = $buf.read-uint16-be();
                my $mx-host = read-dns-name($buf, $raw, $start-offset);
                $rdata-val = sprintf("%d %s", $pref, $mx-host);
            } elsif $rr-type == 16 && $rdlen >= 1 { # TXT
                my $txt-len = $buf.read-uint8();
                if $txt-len <= $rdlen - 1 {
                    $rdata-val = $buf.read-ascii($txt-len);
                    $buf.skip($rdlen - 1 - $txt-len) if $rdlen - 1 > $txt-len;
                } else {
                    $buf.skip($rdlen - 1);
                }
            } else {
                my $raw-rdata = $buf.read-bytes($rdlen);
                $rdata-val = sprintf("[%d bytes]", $rdlen);
            }

            @rrs.push({ name => $rr-name, type => $rr-type, ttl => $ttl, rdata => $rdata-val });
            $fl.add(Sigil::Core::StringField.new(
                :name(sprintf("%s (%s)", $section-name, %qtypes{$rr-type} // $rr-type)),
                :key($key-prefix ~ ".rdata"),
                :value(sprintf("%s -> %s (TTL=%d)", $rr-name, $rdata-val, $ttl))
            ));
        }
        return @rrs;
    }

    my @answers = parse-rr-section($an-count, "Answer", "dns.resp");
    my @authorities = parse-rr-section($ns-count, "Authority", "dns.auth");
    my @additionals = parse-rr-section($ar-count, "Additional", "dns.add");

    my $header-len = $buf.offset - $start-offset;
    my $raw-header = $raw.subbuf($start-offset, $header-len);

    # Generate informative summary representation
    my $type-str = $qr == 1 ?? "response" !! "query";
    my $q-summary = @questions.elems > 0 ?? @questions[0]<name> !! "id=0x" ~ sprintf("%04x", $tx-id);
    my $disp = sprintf("DNS Standard %s %s (%s)", $type-str, $q-summary, %rcodes{$rcode} // "code $rcode");

    return Sigil::Core::Layer.new(
        :name("DNS"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length(0),
        :raw-header($raw-header),
        :raw-payload(Buf.new),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
