# Sigil::Grammar::Protocol::TLS - Transport Layer Security record dissector (RFC 8446)
#
# Parses TLS record layer framing (Handshake, Application Data, Alert, ChangeCipherSpec),
# decodes ClientHello/ServerHello messages, and extracts Server Name Indication (SNI) hostnames.

unit class Sigil::Grammar::Protocol::TLS;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing TLS record
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Minimum TLS record header requires 5 bytes
    if $buf.remaining < 5 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("TLS"),
            :display-name("TLS (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("TLS record truncated: expected at least 5 bytes for record header")
        );
    }

    my $start-offset = $buf.offset;
    my $content-type = $buf.read-uint8();
    my $legacy-version = $buf.read-uint16-be();
    my $record-len = $buf.read-uint16-be();

    my %content-types = (
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        24 => "Heartbeat"
    );

    my %versions = (
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3"
    );

    my %handshake-types = (
        0  => "HelloRequest",
        1  => "ClientHello",
        2  => "ServerHello",
        4  => "NewSessionTicket",
        8  => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::EnumField.new(
        :name("Content Type"),
        :key("tls.record.content_type"),
        :offset-bytes(0),
        :length-bytes(1),
        :value($content-type),
        :name-map(%content-types)
    ));

    $fl.add(Sigil::Core::EnumField.new(
        :name("Legacy Version"),
        :key("tls.record.version"),
        :offset-bytes(1),
        :length-bytes(2),
        :value($legacy-version),
        :name-map(%versions)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Record Length"),
        :key("tls.record.length"),
        :offset-bytes(3),
        :length-bytes(2),
        :value($record-len)
    ));

    my $header-len = 5;
    my $disp-extra = %content-types{$content-type} // sprintf("Type %d", $content-type);
    my $sni-hostname = "";

    # Parse Handshake Protocol (ContentType == 22)
    if $content-type == 22 && $buf.remaining >= 4 {
        my $hs-start = $buf.offset;
        my $hs-type = $buf.read-uint8();
        my $hs-len = $buf.read-uint24-be();

        my $hs-name = %handshake-types{$hs-type} // sprintf("Type %d", $hs-type);
        $disp-extra ~= " (" ~ $hs-name ~ ")";

        $fl.add(Sigil::Core::EnumField.new(
            :name("Handshake Type"),
            :key("tls.handshake.type"),
            :offset-bytes(5),
            :length-bytes(1),
            :value($hs-type),
            :name-map(%handshake-types)
        ));

        $fl.add(Sigil::Core::IntField.new(
            :name("Handshake Length"),
            :key("tls.handshake.length"),
            :offset-bytes(6),
            :length-bytes(3),
            :value($hs-len)
        ));

        # Detailed ClientHello dissection (Handshake Type == 1)
        if $hs-type == 1 && $buf.remaining >= 34 {
            my $client-ver = $buf.read-uint16-be();
            my $random = $buf.read-bytes(32);

            $fl.add(Sigil::Core::EnumField.new(
                :name("Client Hello Version"),
                :key("tls.handshake.client_version"),
                :value($client-ver),
                :name-map(%versions)
            ));

            # Session ID
            if $buf.remaining >= 1 {
                my $sess-id-len = $buf.read-uint8();
                if $sess-id-len > 0 && $buf.remaining >= $sess-id-len {
                    $buf.skip($sess-id-len);
                }
            }

            # Cipher Suites
            if $buf.remaining >= 2 {
                my $cipher-len = $buf.read-uint16-be();
                if $cipher-len > 0 && $buf.remaining >= $cipher-len {
                    $buf.skip($cipher-len);
                }
            }

            # Compression Methods
            if $buf.remaining >= 1 {
                my $comp-len = $buf.read-uint8();
                if $comp-len > 0 && $buf.remaining >= $comp-len {
                    $buf.skip($comp-len);
                }
            }

            # Extensions block
            if $buf.remaining >= 2 {
                my $ext-total-len = $buf.read-uint16-be();
                my $ext-consumed = 0;

                while $ext-consumed + 4 <= $ext-total-len && $buf.remaining >= 4 {
                    my $ext-type = $buf.read-uint16-be();
                    my $ext-len  = $buf.read-uint16-be();
                    $ext-consumed += 4;

                    if $buf.remaining < $ext-len {
                        last;
                    }

                    # Extension 0: Server Name Indication (SNI)
                    if $ext-type == 0 && $ext-len >= 5 {
                        my $sni-list-len = $buf.read-uint16-be();
                        my $sni-name-type = $buf.read-uint8();
                        my $sni-name-len  = $buf.read-uint16-be();

                        if $buf.remaining >= $sni-name-len {
                            $sni-hostname = $buf.read-ascii($sni-name-len);
                            $fl.add(Sigil::Core::StringField.new(
                                :name("Server Name Indication (SNI)"),
                                :key("tls.handshake.sni"),
                                :value($sni-hostname)
                            ));
                            $disp-extra ~= " SNI=" ~ $sni-hostname;
                        }
                        $ext-consumed += $ext-len;
                    } else {
                        $buf.skip($ext-len);
                        $ext-consumed += $ext-len;
                    }
                }
            }
        }
        $header-len = min($raw.elems - $start-offset, 5 + 4 + $hs-len);
    }

    my $raw-header = $raw.subbuf($start-offset, min($header-len, $raw.elems - $start-offset));
    my $avail-payload = $raw.elems - ($start-offset + $header-len);
    my $raw-payload = $avail-payload > 0 ?? $raw.subbuf($start-offset + $header-len) !! Buf.new;

    my $ver-str = %versions{$legacy-version} // sprintf("0x%04x", $legacy-version);
    my $disp = sprintf("TLS Record [%s] %s (Len=%d)", $ver-str, $disp-extra, $record-len);

    return Sigil::Core::Layer.new(
        :name("TLS"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
