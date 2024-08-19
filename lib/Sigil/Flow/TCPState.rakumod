# Sigil::Flow::TCPState - RFC 793 / RFC 9293 state transition engine
#
# Tracks TCP connection lifecycle transitions (Handshake, Established, Teardown, Reset).

unit class Sigil::Flow::TCPState;

use Sigil::Types;

has TCPState $.client-state = TCP_STATE_LISTEN;
has TCPState $.server-state = TCP_STATE_LISTEN;
has Bool $.is-established = False;
has Bool $.is-closed = False;
has Bool $.is-reset = False;

# Process TCP packet flags and transition session state machine
method process-flags(Int $flags, Bool $is-client-to-server) {
    my $syn = ($flags +& TCP_SYN) != 0;
    my $ack = ($flags +& TCP_ACK) != 0;
    my $fin = ($flags +& TCP_FIN) != 0;
    my $rst = ($flags +& TCP_RST) != 0;

    # Reset immediately aborts connection
    if $rst {
        $!is-reset = True;
        $!is-closed = True;
        $!is-established = False;
        $!client-state = TCP_STATE_CLOSED;
        $!server-state = TCP_STATE_CLOSED;
        return;
    }

    if $is-client-to-server {
        # Client to Server transitions
        if $syn && !$ack {
            if $!client-state == TCP_STATE_LISTEN {
                $!client-state = TCP_STATE_SYN_SENT;
            }
        } elsif $ack && !$syn && !$fin {
            if $!server-state == TCP_STATE_SYN_RECEIVED {
                $!client-state = TCP_STATE_ESTABLISHED;
                $!server-state = TCP_STATE_ESTABLISHED;
                $!is-established = True;
            } elsif $!client-state == TCP_STATE_FIN_WAIT_1 {
                $!client-state = TCP_STATE_FIN_WAIT_2;
            } elsif $!client-state == TCP_STATE_LAST_ACK {
                $!client-state = TCP_STATE_CLOSED;
                $!is-closed = True;
            }
        } elsif $fin {
            if $!client-state == TCP_STATE_ESTABLISHED {
                $!client-state = TCP_STATE_FIN_WAIT_1;
            } elsif $!client-state == TCP_STATE_CLOSE_WAIT {
                $!client-state = TCP_STATE_LAST_ACK;
            }
        }
    } else {
        # Server to Client transitions
        if $syn && $ack {
            if $!client-state == TCP_STATE_SYN_SENT {
                $!server-state = TCP_STATE_SYN_RECEIVED;
            }
        } elsif $ack && !$syn && !$fin {
            if $!server-state == TCP_STATE_LAST_ACK {
                $!server-state = TCP_STATE_CLOSED;
                $!is-closed = True;
            } elsif $!server-state == TCP_STATE_FIN_WAIT_1 {
                $!server-state = TCP_STATE_FIN_WAIT_2;
            }
        } elsif $fin {
            if $!server-state == TCP_STATE_ESTABLISHED {
                $!server-state = TCP_STATE_FIN_WAIT_1;
            } elsif $!server-state == TCP_STATE_CLOSE_WAIT {
                $!server-state = TCP_STATE_LAST_ACK;
            }
        }
    }

    if $!client-state == TCP_STATE_CLOSED && $!server-state == TCP_STATE_CLOSED {
        $!is-closed = True;
    }
}

# Formatted state string
method summary(--> Str) {
    if $!is-reset {
        return "RESET";
    } elsif $!is-closed {
        return "CLOSED";
    } elsif $!is-established {
        return "ESTABLISHED";
    } else {
        my $c = $!client-state.key.subst(/^TCP_STATE_/, '');
        my $s = $!server-state.key.subst(/^TCP_STATE_/, '');
        return sprintf("C:%s/S:%s", $c, $s);
    }
}
