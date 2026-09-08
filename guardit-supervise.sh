#!/usr/bin/env bash
# restart-loop supervisor for systems without systemd (or if you just don't
# want the unit). Applies the ruleset then keeps the daemon running,
# restarting it 1s after any crash/exit — same "always on" guarantee as
# guardit.service, just dumber.
set -u

while true; do
    /usr/local/bin/guardit apply
    /usr/local/bin/guardit daemon
    echo "guardit daemon exited — restarting in 1s" >&2
    sleep 1
done
