# Sigil::Grammar::Common - Shared lexical tokens and RFC 5234 ABNF primitives
#
# Provides reusable grammar rules, delimiters, address patterns,
# and header tokenizers across all higher-layer text protocols.

unit grammar Sigil::Grammar::Common;

# Core ABNF terminal tokens (RFC 5234)
token crlf       { \r\n | \n }
token sp         { ' ' }
token htab       { \t }
token wsp        { <[ \t]> }
token ows        { <[ \t]>* }
token rws        { <[ \t]>+ }
token octet      { \x00..\xFF }
token vchar      { \x21..\x7E }

# Basic token characters (RFC 7230 tchar for HTTP header names and methods)
token tchar      { <[-0..9a..zA..Z!#$%&'*+.^_`|~]> }
token token-word { <tchar>+ }

# Numeric tokens
token digit      { \d }
token digits     { \d+ }
token hexdigit   { <[0..9a..fA..F]> }
token hex-byte   { <hexdigit>**2 }
token hex-word16 { <hexdigit>**4 }
token hex-word32 { <hexdigit>**8 }

# Network address lexical patterns
token mac-octet  { <hexdigit>**2 }
token mac-addr   { <mac-octet> ** 6 % ':' }

token ipv4-octet { (\d**1..3) <?{ $0.Int <= 255 }> }
token ipv4-addr  { <ipv4-octet> ** 4 % '.' }

token ipv6-piece { <hexdigit>**1..4 }
token ipv6-full  { <ipv6-piece> ** 8 % ':' }

# Quoted string and escaped characters
token qdtext     { <[ \t\x21\x23..\x5B\x5D..\x7E]> }
token quoted-str { '"' [ <qdtext> | '\\' <vchar> ]* '"' }

# Base64 tokens
token b64-char   { <[A..Za..z0..9+/]> }
token b64-padded { <b64-char>+ '='* }

# URI components (RFC 3986)
token scheme     { <[a..zA..Z]> <[-a..zA..Z0..9+.]>* }
token port-num   { (\d**1..5) <?{ $0.Int <= 65535 }> }
token path-seg   { <[-a..zA..Z0..9._~%!$&'()*+,;=:@]>* }
token abs-path   { '/' [ <path-seg> ]* % '/' }
