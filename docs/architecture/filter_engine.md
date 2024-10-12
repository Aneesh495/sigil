# Packet Filter DSL & Compiler Architecture

The Sigil Packet Filter DSL provides an expressive, readable query language for packet capture inspection and stream slicing. Filter expressions compile into native executable closures that evaluate in microseconds per frame.

```
+-----------------------------------------------------------------------------+
|                         FILTER COMPILATION PIPELINE                         |
+-----------------------------------------------------------------------------+
|                                                                             |
|   Query: "ip.proto == 6 && (tcp.dstport == 80 || tcp.dstport == 443)"       |
|                                                                             |
|   1. Lexical & Syntactic Analysis (Sigil::Filter::Grammar)                  |
|      - Parses tokens with operator precedence: NOT > AND > OR               |
|      - Extracts field keys, relational operators, and numeric literals      |
|                                                                             |
|   2. AST Node Construction (Sigil::Filter::Actions)                         |
|                                                                             |
|                           [ AndNode ]                                       |
|                            /       \                                        |
|             [ CompareNode ]         [ OrNode ]                              |
|             (ip.proto == 6)          /      \                               |
|                       [ CompareNode ]        [ CompareNode ]                |
|                      (tcp.dstport==80)      (tcp.dstport==443)              |
|                                                                             |
|   3. JIT Closure Generation (Sigil::Filter::Compiler)                       |
|      - Compiles composite AST into high-speed callable predicate:           |
|        sub (Packet $pkt --> Bool) { ... }                                   |
|      - Stores compiled predicate in LRU cache                               |
|                                                                             |
|   4. Execution (Sigil::Filter::Engine)                                      |
|      - Evaluates stream with short-circuit boolean semantics                |
|      - Yields matching packets with zero runtime string re-parsing          |
+-----------------------------------------------------------------------------+
```

## Language Syntax & Features

### Relational Comparisons
```
ip.proto == 6
tcp.dstport == 80
ip.ttl < 64
frame.len >= 128
```

### String Matching
```
http.request.method == 'GET'
http.request.uri contains '/api/v1'
dns.qry.name contains 'google'
```

### CIDR Subnet Containment
Tests whether IPv4 address falls within a Classless Inter-Domain Routing prefix:
```
ip.src in 192.168.1.0/24
ip.dst in 10.0.0.0/8
```

### Set Membership
Tests whether integer or string belongs to an enumeration set:
```
tcp.dstport in [80, 443, 8080, 8443]
http.request.method in ['GET', 'POST', 'PUT']
```

### Boolean Logic & Precedence
Parentheses override standard precedence:
```
(ip.src == 10.0.0.1 || ip.src == 10.0.0.2) && !(tcp.dstport == 22)
```

## Compiler Optimizations

1. **Short-Circuit Evaluation**: Logical `AndNode` evaluates left operand first; if false, right subtree evaluation is skipped immediately. Similarly, `OrNode` skips right subtree if left is true.
2. **Deep Field Resolution**: Field lookups check indexed layer caches before falling back to recursive layer traversal.
3. **Closure Cache**: `Sigil::Filter::Compiler` caches compiled closures by expression string. Re-filtering across multiple trace files avoids repeated grammar parses.
