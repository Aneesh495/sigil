# Authoring Custom Protocol Dissectors

Sigil allows developers to extend the dissection pipeline with custom protocols without modifying the core engine. Protocol dissectors can decode binary frames using `Sigil::Core::Buffer` or text framing using native Raku Grammars.

## Protocol Dissector Contract

Every dissector is a class implementing a `dissect()` method returning a `Sigil::Core::Layer`:

```raku
unit class Sigil::Grammar::Protocol::MyProto;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;

method protocol-name(--> Str) { return "MYPROTO"; }

method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));
    my $start = $offset;

    # 1. Bounds checking
    if $buf.remaining < 8 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("MYPROTO"),
            :display-name("MyProto (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining()),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED)
        );
    }

    # 2. Field decoding
    my $magic = $buf.read-uint32-be();
    my $version = $buf.read-uint16-be();
    my $payload-len = $buf.read-uint16-be();

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::IntField.new(:name("Magic"), :key("myproto.magic"), :value($magic), :radix("hex"), :bit-width(32)));
    $fl.add(Sigil::Core::IntField.new(:name("Version"), :key("myproto.version"), :value($version)));
    $fl.add(Sigil::Core::IntField.new(:name("Payload Length"), :key("myproto.len"), :value($payload-len)));

    # 3. Payload slicing
    my $header-len = $buf.offset - $start;
    my $payload = $buf.read-bytes($payload-len);

    return Sigil::Core::Layer.new(
        :name("MYPROTO"),
        :display-name("MyProto v$version"),
        :offset($offset),
        :header-length($header-len),
        :payload-length($payload.elems),
        :raw-header($raw.subbuf($start, $header-len)),
        :raw-payload($payload),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
```

## Registering into the Dispatch Pipeline

Dissectors are registered with `Sigil::Core::Registry`:

### Static Registration by Port / EtherType
```raku
my $registry = Sigil::Core::Registry.instance;

# Register as UDP port 9999
$registry.register-selector("UDP", 9999, Sigil::Grammar::Protocol::MyProto.new);

# Or register as link layer EtherType 0x8899
$registry.register-selector("Ethernet", 0x8899, Sigil::Grammar::Protocol::MyProto.new);
```

### Dynamic Heuristic Sniffing
If the protocol operates on dynamic or non-deterministic ports, register a heuristic probe:

```raku
$registry.register-heuristic(sub (Buf $payload, Str $transport --> Bool) {
    return False if $payload.elems < 4;
    # Check if first 4 bytes match magic 0x5052544F ('PRTO')
    return ($payload[0] == 0x50 && $payload[1] == 0x52 && $payload[2] == 0x54 && $payload[3] == 0x4F);
}, Sigil::Grammar::Protocol::MyProto.new);
```

## Dynamic Plugin Loading

Custom dissectors can be saved in a `plugins/` directory and loaded at runtime without recompilation:

```raku
my $plugin-mgr = Sigil::Plugin::Manager.new;
$plugin-mgr.load-dissector("Sigil::Grammar::Protocol::MyProto");
```
