# Sigil::Grammar::Protocol::NTP - Network Time Protocol v4 dissector (RFC 5905)
#
# Parses 48-byte NTP fixed headers, Leap Indicator warnings, Stratum levels,
# Poll/Precision exponents, Reference Identifiers (GPS/PTP/NIST), and 64-bit epoch timestamps.

unit class Sigil::Grammar::Protocol::NTP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing NTP packet
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base NTP packet requires at least 48 bytes
    if $buf.remaining < 48 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("NTP"),
            :display-name("NTP (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("NTP packet truncated: expected at least 48 bytes for base packet")
        );
    }

    my $start-offset = $buf.offset;

    # Byte 0: LI (2 bits), VN (3 bits), Mode (3 bits)
    my $b0 = $buf.read-uint8();
    my $li   = $b0 +> 6;
    my $vn   = ($b0 +> 3) +& 0x07;
    my $mode = $b0 +& 0x07;

    my $stratum   = $buf.read-uint8();
    my $poll      = $buf.read-int8();
    my $precision = $buf.read-int8();

    # Fixed point 32-bit root delay and dispersion (16 bits int, 16 bits frac)
    my $root-delay-raw = $buf.read-uint32-be();
    my $root-delay = ($root-delay-raw +> 16) + (($root-delay-raw +& 0xFFFF) / 65536e0);

    my $root-disp-raw = $buf.read-uint32-be();
    my $root-disp = ($root-disp-raw +> 16) + (($root-disp-raw +& 0xFFFF) / 65536e0);

    # Reference ID (4 bytes)
    my $ref-id-bytes = $buf.read-bytes(4);
    my $ref-id-str = "";
    if $stratum <= 1 { # Primary reference source: 4-character ASCII tag
        $ref-id-str = $ref-id-bytes.decode('ascii').trim;
    } else { # Secondary reference: IPv4 address
        $ref-id-str = $ref-id-bytes.list.join('.');
    }

    # Helper sub to decode 64-bit NTP timestamp into UNIX epoch seconds
    # NTP epoch starts Jan 1 1900; UNIX epoch starts Jan 1 1970 (offset 2,208,988,800 seconds)
    my sub read-ntp-timestamp(Sigil::Core::Buffer $b --> Num) {
        my $sec = $b.read-uint32-be();
        my $frac = $b.read-uint32-be();
        return 0e0 if $sec == 0;
        my $frac-sec = $frac / 4294967296e0;
        my $unix-sec = ($sec - 2208988800) + $frac-sec;
        return $unix-sec;
    }

    my $ref-ts   = read-ntp-timestamp($buf);
    my $orig-ts  = read-ntp-timestamp($buf);
    my $recv-ts  = read-ntp-timestamp($buf);
    my $trans-ts = read-ntp-timestamp($buf);

    my %li-names = (
        0 => "No Warning",
        1 => "Last minute of the day has 61 seconds (Leap second insertion)",
        2 => "Last minute of the day has 59 seconds (Leap second deletion)",
        3 => "Alarm condition (Clock not synchronized)"
    );

    my %mode-names = (
        0 => "Reserved",
        1 => "Symmetric Active",
        2 => "Symmetric Passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "NTP Control Message",
        7 => "Private Use"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::EnumField.new(:name("Leap Indicator"), :key("ntp.flags.li"), :offset-bytes(0), :length-bytes(1), :value($li), :name-map(%li-names)));
    $fl.add(Sigil::Core::IntField.new(:name("Version Number"), :key("ntp.flags.vn"), :offset-bytes(0), :length-bytes(1), :value($vn)));
    $fl.add(Sigil::Core::EnumField.new(:name("Mode"), :key("ntp.flags.mode"), :offset-bytes(0), :length-bytes(1), :value($mode), :name-map(%mode-names)));
    $fl.add(Sigil::Core::IntField.new(:name("Peer Stratum"), :key("ntp.stratum"), :offset-bytes(1), :length-bytes(1), :value($stratum)));
    $fl.add(Sigil::Core::IntField.new(:name("Peer Poll Interval (log2 s)"), :key("ntp.poll"), :offset-bytes(2), :length-bytes(1), :value($poll)));
    $fl.add(Sigil::Core::IntField.new(:name("Peer Precision (log2 s)"), :key("ntp.precision"), :offset-bytes(3), :length-bytes(1), :value($precision)));

    $fl.add(Sigil::Core::StringField.new(:name("Reference ID"), :key("ntp.refid"), :offset-bytes(12), :length-bytes(4), :value($ref-id-str)));
    $fl.add(Sigil::Core::StringField.new(:name("Reference Timestamp"), :key("ntp.reftime"), :offset-bytes(16), :length-bytes(8), :value(sprintf("%.6f", $ref-ts))));
    $fl.add(Sigil::Core::StringField.new(:name("Origin Timestamp"), :key("ntp.orgtime"), :offset-bytes(24), :length-bytes(8), :value(sprintf("%.6f", $orig-ts))));
    $fl.add(Sigil::Core::StringField.new(:name("Receive Timestamp"), :key("ntp.recvtime"), :offset-bytes(32), :length-bytes(8), :value(sprintf("%.6f", $recv-ts))));
    $fl.add(Sigil::Core::StringField.new(:name("Transmit Timestamp"), :key("ntp.xmittime"), :offset-bytes(40), :length-bytes(8), :value(sprintf("%.6f", $trans-ts))));

    my $raw-header = $raw.subbuf($start-offset, 48);
    my $mode-title = %mode-names{$mode} // sprintf("Mode %d", $mode);
    my $disp = sprintf("NTP v%d (%s, Stratum %d, RefID=%s)", $vn, $mode-title, $stratum, $ref-id-str);

    return Sigil::Core::Layer.new(
        :name("NTP"),
        :display-name($disp),
        :offset($offset),
        :header-length(48),
        :payload-length(0),
        :raw-header($raw-header),
        :raw-payload(Buf.new),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
