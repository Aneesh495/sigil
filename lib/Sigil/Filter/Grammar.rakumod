# Sigil::Filter::Grammar - Lexical grammar for packet filter expressions
#
# Parses BPF-like predicate filters, relational comparisons, string matching,
# CIDR containment, and boolean operator precedences (NOT > AND > OR).

unit grammar Sigil::Filter::Grammar;

rule TOP {
    <or-expr>
}

rule or-expr {
    <and-expr>+ % [ 'or' | '||' ]
}

rule and-expr {
    <not-expr>+ % [ 'and' | '&&' ]
}

rule not-expr {
    | [ 'not' | '!' ] <not-expr>
    | <primary-expr>
}

rule primary-expr {
    | '(' <or-expr> ')'
    | <cidr-pred>
    | <contains-pred>
    | <in-set-pred>
    | <compare-pred>
    | <proto-pred>
}

rule proto-pred {
    <proto-name>
}

token proto-name {
    <[a..zA..Z0..9_-]>+
}

rule compare-pred {
    <field-key> <comp-op> <value>
}

token comp-op {
    '==' | '!=' | '<=' | '>=' | '<' | '>'
}

rule contains-pred {
    <field-key> 'contains' <string-val>
}

rule in-set-pred {
    <field-key> 'in' '[' <value-list> ']'
}

rule value-list {
    <value>+ % ','
}

rule cidr-pred {
    <field-key> 'in' <cidr-val>
}

token cidr-val {
    (\d**1..3) '.' (\d**1..3) '.' (\d**1..3) '.' (\d**1..3) '/' (\d**1..2)
}

token field-key {
    <[a..zA..Z]> <[a..zA..Z0..9._-]>*
}

token value {
    | <string-val>
    | <hex-num>
    | <ip-addr-val>
    | <dec-num>
}

token ip-addr-val {
    (\d**1..3) '.' (\d**1..3) '.' (\d**1..3) '.' (\d**1..3)
}

token dec-num {
    '-'? \d+
}

token hex-num {
    '0x' <[0..9a..fA..F]>+
}

token string-val {
    | '"' (<-["]>*) '"'
    | '\'' (<-[']>*) '\''
}
