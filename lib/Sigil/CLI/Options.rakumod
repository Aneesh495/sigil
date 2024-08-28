# Sigil::CLI::Options - Command line argument parsing and configuration
#
# Parses flags, subcommands, filter expressions, and output formats for the
# unified Sigil binary toolchain.

unit class Sigil::CLI::Options;

has Str $.subcommand = "dissect";
has Str $.filepath = "";
has Str $.filter-expr = "";
has Str $.format = "text";                   # text, json, ndjson, csv, hex
has Bool $.show-tree = False;
has Num $.rate-multiplier = 0e0;
has Int $.packet-limit = 0;
has Bool $.verbose = False;
has Bool $.show-help = False;

# Parse command line argument array
method parse(@args --> Sigil::CLI::Options) {
    my $sub = "dissect";
    my $file = "";
    my $filt = "";
    my $fmt = "text";
    my $tree = False;
    my $rate = 0e0;
    my $limit = 0;
    my $verb = False;
    my $help = False;

    my @rest = @args;
    if @rest.elems > 0 && !@rest[0].starts-with("-") {
        $sub = @rest.shift;
    }

    while @rest.elems > 0 {
        my $arg = @rest.shift;
        given $arg {
            when "-r" | "--read" {
                $file = @rest.shift if @rest.elems > 0;
            }
            when "-f" | "--filter" {
                $filt = @rest.shift if @rest.elems > 0;
            }
            when "--format" {
                $fmt = @rest.shift if @rest.elems > 0;
            }
            when "-V" | "--tree" {
                $tree = True;
            }
            when "--rate" {
                $rate = @rest.shift.Num if @rest.elems > 0;
            }
            when "-c" | "--count" {
                $limit = @rest.shift.Int if @rest.elems > 0;
            }
            when "-v" | "--verbose" {
                $verb = True;
            }
            when "-h" | "--help" {
                $help = True;
            }
            default {
                if $file eq "" && !$arg.starts-with("-") {
                    $file = $arg;
                }
            }
        }
    }

    return self.new(
        :subcommand($sub),
        :filepath($file),
        :filter-expr($filt),
        :format($fmt),
        :show-tree($tree),
        :rate-multiplier($rate),
        :packet-limit($limit),
        :verbose($verb),
        :show-help($help)
    );
}

# Print help banner
method usage(--> Str) {
    return q:to/USAGE/;
Usage: sigil <command> [options] [trace.pcap]

Commands:
  dissect   Dissect packets from PCAP/PCAPNG trace file
  flow      Track bidirectional TCP/UDP flows and reassemble streams
  stats     Aggregate protocol telemetry, heavy hitters, and anomalies
  entropy   Scan payloads and DNS queries for high-entropy obfuscation
  pcapng    Inspect Section, Interface, and Enhanced Packet Blocks
  filter    Validate and evaluate BPF-like filter expressions

Options:
  -r, --read <file>     Input PCAP or PCAPNG trace file
  -f, --filter <expr>   Packet filter expression (e.g. "tcp.dstport == 80")
  --format <fmt>        Output format: text (default), json, ndjson, csv, hex
  -V, --tree            Expand complete protocol hierarchy tree
  --rate <multiplier>   Replay pacing multiplier (1.0 = real-time, 0 = line rate)
  -c, --count <n>       Maximum number of packets to process
  -v, --verbose         Enable diagnostic debug logging
  -h, --help            Show this help reference
USAGE
}
