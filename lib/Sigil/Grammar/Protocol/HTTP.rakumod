# Sigil::Grammar::Protocol::HTTP - Hypertext Transfer Protocol 1.1 dissector (RFC 7230)
#
# Implements native Raku Grammar for HTTP/1.1 request/response lines, RFC 7230 ABNF
# header tokenization, case-insensitive header mapping, and body extraction.

unit class Sigil::Grammar::Protocol::HTTP;

use Sigil::Types;
use Sigil::Grammar::Common;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Native Raku Grammar for parsing HTTP/1.1 text framing
grammar Parser is Sigil::Grammar::Common {
    token TOP {
        [ <request-line> | <status-line> ]
        <header-line>*
        <crlf>
    }

    token request-line {
        <http-method> <sp> <request-target> <sp> <http-version> <crlf>
    }

    token http-method {
        'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'PATCH' | 'CONNECT' | 'TRACE'
    }

    token request-target {
        \S+
    }

    token http-version {
        'HTTP/' \d+ '.' \d+
    }

    token status-line {
        <http-version> <sp> <resp-code> [ <sp> <status-phrase> ]? <crlf>
    }

    token resp-code {
        \d**3
    }

    token status-phrase {
        \N+
    }

    token header-line {
        <token-word> ':' <ows> <header-val> <crlf>
    }

    token header-val {
        \N*
    }
}

# Action class for transforming AST into structured Layer fields
class Actions {
    has %.headers;
    has Str $.method = "";
    has Str $.uri = "";
    has Str $.version = "";
    has Int $.status-code = 0;
    has Str $.reason-phrase = "";
    has Bool $.is-request = False;
    has Bool $.is-response = False;

    method request-line($/) {
        $!is-request = True;
        $!method = ~$<http-method>;
        $!uri = ~$<request-target>;
        $!version = ~$<http-version>;
    }

    method status-line($/) {
        $!is-response = True;
        $!version = ~$<http-version>;
        $!status-code = $<resp-code>.Int;
        $!reason-phrase = $<status-phrase>.defined ?? ~$<status-phrase>.trim !! "";
    }

    method header-line($/) {
        my $k = ~$<token-word>.lc;
        my $v = ~$<header-val>.trim;
        %!headers{$k} = $v;
    }
}

# Dissect raw byte buffer containing HTTP stream data
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    # Check minimum text length
    if $raw.elems - $offset < 8 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("HTTP"),
            :display-name("HTTP (Truncated)"),
            :offset($offset),
            :header-length($raw.elems - $offset),
            :payload-length(0),
            :raw-header($raw.subbuf($offset)),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("HTTP message truncated: insufficient bytes for request/status line")
        );
    }

    my $slice = $raw.subbuf($offset);
    # Convert bytes to string (Latin-1 / UTF-8 fallback for ASCII headers)
    my $text = "";
    try {
        $text = $slice.decode('latin-1');
    }
    if $text eq "" {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("HTTP"),
            :display-name("HTTP (Decode Error)"),
            :offset($offset),
            :header-length(0),
            :payload-length(0),
            :raw-header(Buf.new),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_MALFORMED),
            :status-detail("Failed to decode ASCII text stream for HTTP")
        );
    }

    # Locate end of HTTP header block (\r\n\r\n or \n\n)
    my $header-end-idx = -1;
    my $header-delimiter-len = 0;
    if my $m = $text ~~ /\r?\n\r?\n/ {
        $header-end-idx = $m.from;
        $header-delimiter-len = $m.chars;
    } else {
        # Partial or incomplete header block
        $header-end-idx = $text.chars;
    }

    my $header-block = $text.substr(0, $header-end-idx + $header-delimiter-len);
    my $actions = Actions.new;
    my $match = Parser.parse($header-block, :actions($actions));

    my $fl = Sigil::Core::FieldList.new;
    my $status = STATUS_OK;
    my $status-detail = "";
    my $disp = "HTTP";

    if $match {
        if $actions.is-request {
            $disp = sprintf("HTTP %s %s (%s)", $actions.method, $actions.uri, $actions.version);
            $fl.add(Sigil::Core::StringField.new(:name("Request Method"), :key("http.request.method"), :value($actions.method)));
            $fl.add(Sigil::Core::StringField.new(:name("Request URI"), :key("http.request.uri"), :value($actions.uri)));
            $fl.add(Sigil::Core::StringField.new(:name("Request Version"), :key("http.request.version"), :value($actions.version)));
        } elsif $actions.is-response {
            $disp = sprintf("HTTP %s %d %s", $actions.version, $actions.status-code, $actions.reason-phrase);
            $fl.add(Sigil::Core::IntField.new(:name("Status Code"), :key("http.response.code"), :value($actions.status-code)));
            $fl.add(Sigil::Core::StringField.new(:name("Reason Phrase"), :key("http.response.phrase"), :value($actions.reason-phrase)));
            $fl.add(Sigil::Core::StringField.new(:name("Response Version"), :key("http.response.version"), :value($actions.version)));
        }

        # Add indexed common HTTP headers
        for $actions.headers.kv -> $k, $v {
            my $field-name = $k.split('-').map(*.tc).join('-');
            $fl.add(Sigil::Core::StringField.new(
                :name($field-name),
                :key("http.header." ~ $k.subst('-', '_', :g)),
                :value($v)
            ));
        }

        # Specialized lookups
        if $actions.headers<host>:exists {
            $fl.add(Sigil::Core::StringField.new(:name("Host"), :key("http.host"), :value($actions.headers<host>)));
        }
        if $actions.headers<content-length>:exists {
            $fl.add(Sigil::Core::IntField.new(:name("Content Length"), :key("http.content_length"), :value($actions.headers<content-length>.Int)));
        }
        if $actions.headers<content-type>:exists {
            $fl.add(Sigil::Core::StringField.new(:name("Content Type"), :key("http.content_type"), :value($actions.headers<content-type>)));
        }
    } else {
        $status = STATUS_MALFORMED;
        $status-detail = "Failed to parse HTTP request/status line with grammar";
        $disp = "HTTP (Malformed)";
    }

    my $header-byte-len = $header-block.encode('latin-1').elems;
    my $raw-header = $raw.subbuf($offset, min($header-byte-len, $raw.elems - $offset));
    my $avail-body = $raw.elems - ($offset + $header-byte-len);
    my $raw-payload = $avail-body > 0 ?? $raw.subbuf($offset + $header-byte-len) !! Buf.new;

    return Sigil::Core::Layer.new(
        :name("HTTP"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-byte-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status($status),
        :status-detail($status-detail),
        :next-protocol(Nil)
    );
}
