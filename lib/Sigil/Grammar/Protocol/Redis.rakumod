# Sigil::Grammar::Protocol::Redis - Redis Serialization Protocol (RESP2 / RESP3) dissector
#
# Parses RESP framing prefixes (+Strings, -Errors, :Integers, $BulkStrings, *Arrays),
# extracts Redis command verbs, keys, argument arrays, and RESP3 type extensions.

unit class Sigil::Grammar::Protocol::Redis;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing Redis RESP stream
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    if $raw.elems - $offset < 3 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("Redis"),
            :display-name("Redis (Truncated)"),
            :offset($offset),
            :header-length($raw.elems - $offset),
            :payload-length(0),
            :raw-header($raw.subbuf($offset)),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("Redis RESP message truncated: insufficient bytes")
        );
    }

    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));
    my $start-offset = $buf.offset;

    my $prefix-byte = $buf.read-uint8();
    my $prefix-char = $prefix-byte.chr;

    my %resp-types = (
        '+' => "Simple String",
        '-' => "Error",
        ':' => "Integer",
        '$' => "Bulk String",
        '*' => "Array",
        '_' => "Null (RESP3)",
        '#' => "Boolean (RESP3)",
        ',' => "Double (RESP3)",
        '%' => "Map (RESP3)"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::StringField.new(
        :name("RESP Type"),
        :key("redis.type"),
        :offset-bytes(0),
        :length-bytes(1),
        :value(%resp-types{$prefix-char} // "Unknown")
    ));

    my $cmd-name = "";
    my @args;
    my $summary-extra = "";

    # Helper sub to read line ending in \r\n
    my sub read-resp-line(Sigil::Core::Buffer $b --> Str) {
        my @chars;
        while $b.remaining > 0 {
            my $ch = $b.read-uint8();
            if $ch == 0x0D && $b.remaining > 0 && $b.peek-uint8(0) == 0x0A {
                $b.read-uint8(); # Consume 0x0A
                last;
            }
            @chars.push($ch.chr);
        }
        return @chars.join('');
    }

    if $prefix-char eq '*' { # Array (standard Redis client command invocation)
        my $line = read-resp-line($buf);
        my $elem-count = $line.Int;
        $fl.add(Sigil::Core::IntField.new(:name("Array Length"), :key("redis.array_len"), :value($elem-count)));

        for 0 ..^ $elem-count {
            last if $buf.at-eof;
            my $item-prefix = $buf.read-uint8().chr;
            if $item-prefix eq '$' { # Bulk string
                my $len-line = read-resp-line($buf);
                my $str-len = $len-line.Int;
                if $str-len >= 0 && $buf.remaining >= $str-len {
                    my $str-val = $buf.read-ascii($str-len);
                    # Consume trailing CRLF
                    $buf.skip(2) if $buf.remaining >= 2;
                    @args.push($str-val);
                }
            } else {
                my $val = read-resp-line($buf);
                @args.push($val);
            }
        }

        if @args.elems > 0 {
            $cmd-name = @args[0].uc;
            $fl.add(Sigil::Core::StringField.new(:name("Command"), :key("redis.command"), :value($cmd-name)));
            if @args.elems > 1 {
                $fl.add(Sigil::Core::StringField.new(:name("Key"), :key("redis.key"), :value(@args[1])));
                $summary-extra = sprintf("%s %s", $cmd-name, @args[1]);
            } else {
                $summary-extra = $cmd-name;
            }
        }
    } elsif $prefix-char eq '+' { # Simple String
        my $str = read-resp-line($buf);
        $fl.add(Sigil::Core::StringField.new(:name("Value"), :key("redis.value"), :value($str)));
        $summary-extra = $str;
    } elsif $prefix-char eq '-' { # Error
        my $err = read-resp-line($buf);
        $fl.add(Sigil::Core::StringField.new(:name("Error Message"), :key("redis.error"), :value($err)));
        $summary-extra = "ERR: " ~ $err;
    } elsif $prefix-char eq ':' { # Integer
        my $num-str = read-resp-line($buf);
        $fl.add(Sigil::Core::IntField.new(:name("Integer Value"), :key("redis.integer"), :value($num-str.Int)));
        $summary-extra = ":" ~ $num-str;
    } elsif $prefix-char eq '$' { # Bulk String
        my $len-line = read-resp-line($buf);
        my $str-len = $len-line.Int;
        if $str-len == -1 {
            $fl.add(Sigil::Core::StringField.new(:name("Bulk String"), :key("redis.bulk_string"), :value("nil")));
            $summary-extra = "nil";
        } elsif $str-len >= 0 && $buf.remaining >= $str-len {
            my $str-val = $buf.read-ascii($str-len);
            $buf.skip(2) if $buf.remaining >= 2;
            $fl.add(Sigil::Core::StringField.new(:name("Bulk String"), :key("redis.bulk_string"), :value($str-val)));
            $summary-extra = '"' ~ $str-val ~ '"';
        }
    }

    my $header-len = $buf.offset - $start-offset;
    my $raw-header = $raw.subbuf($start-offset, $header-len);
    my $disp = $summary-extra ne ""
        ?? sprintf("Redis RESP (%s)", $summary-extra)
        !! sprintf("Redis RESP [%s]", %resp-types{$prefix-char} // $prefix-char);

    return Sigil::Core::Layer.new(
        :name("Redis"),
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
