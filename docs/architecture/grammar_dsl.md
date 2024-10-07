# Protocol Grammar DSL & Dissection Architecture

Sigil leverages Raku's first-class Grammar engine, action classes, and typed buffer cursors to deliver clear, declarative, and defensive protocol dissectors.

```
+-----------------------------------------------------------------------------+
|                          PROTOCOL DISSECTION MODEL                          |
+-----------------------------------------------------------------------------+
|                                                                             |
|   Raw Wire Frame: [ Eth Hdr | IP Hdr | TCP Hdr | HTTP Payload ]             |
|                                                                             |
|      Layer 2 (Ethernet)                                                     |
|      +-------------------------------------------------------------------+  |
|      | Dest MAC | Source MAC | EtherType (0x0800)                        |  |
|      +-------------------------------------------------------------------+  |
|                           |                                                 |
|                           v  Registry Lookup: EtherType 0x0800 -> IPv4      |
|      Layer 3 (IPv4)                                                         |
|      +-------------------------------------------------------------------+  |
|      | Ver/IHL | ToS | Total Len | Ident | TTL | Proto (6) | Checksum | IPs|  |
|      +-------------------------------------------------------------------+  |
|                           |                                                 |
|                           v  Registry Lookup: IP Protocol 6 -> TCP          |
|      Layer 4 (TCP)                                                          |
|      +-------------------------------------------------------------------+  |
|      | Src Port (49152) | Dst Port (80) | Seq | Ack | Flags | Checksum   |  |
|      +-------------------------------------------------------------------+  |
|                           |                                                 |
|                           v  Port 80 / Heuristic Match -> HTTP/1.1          |
|      Layer 7 (HTTP)                                                         |
|      +-------------------------------------------------------------------+  |
|      | Grammar Parse: "GET /index.html HTTP/1.1\r\nHost: example.com..." |  |
|      +-------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------+
```

## Buffer Management & Defensive Cursor Semantics

Binary decoding requires precise byte slicing, bitmask extraction, and bounds checking. The core abstraction is `Sigil::Core::Buffer`:

- **Zero-Copy Sub-Buffers**: Byte slices are extracted via `.subbuf()`, pointing to sliced views of captured frames.
- **Rollback Checkpoints**: For variable-length options or speculative grammars, `.checkpoint()` snapshots the cursor offset and bit-buffer registers. If parsing encounters unexpected format markers or truncated tails, `.rollback()` restores the cursor without memory allocation.
- **Decontainerization**: In Raku, scalar containers can alias mutable object attributes. `Sigil::Core::Buffer` explicitly decontainerizes integer offsets during checkpoint pushes to prevent accidental mutation.

## Text Protocol Parsing via Raku Grammars

For text-based protocols (HTTP/1.1, Redis RESP, Syslog, SIP), Sigil combines regex tokens with action classes:

```raku
grammar HTTP::Parser is Sigil::Grammar::Common {
    token TOP {
        [ <request-line> | <status-line> ]
        <header-line>*
        <crlf>
    }

    token request-line {
        <http-method> <sp> <request-target> <sp> <http-version> <crlf>
    }

    token http-method {
        'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'OPTIONS'
    }
}
```

Action classes process AST nodes and extract typed attributes directly into `Sigil::Core::FieldList`, making fields queryable via both name and filter keys (e.g., `http.request.method`).

## Dynamic Dissector Registry & Heuristics

The `Sigil::Core::Registry` maintains three dispatch tables:
1. **Link Layer Table**: Indexed by PCAP LinkType (Ethernet, Linux SLL, Raw IP).
2. **Selector Table**: Indexed by (Parent Protocol, Selector Value), such as (Ethernet, 0x0800) or (IPv4, 6).
3. **Heuristic Probes**: Ordered chain of callable closures `sub (Buf $payload, Str $transport --> Bool)` executed when destination ports are non-standard or unmapped. Heuristics allow Sigil to detect TLS ClientHello on port 8443, HTTP proxies on port 8080, and SSH on arbitrary ports.
