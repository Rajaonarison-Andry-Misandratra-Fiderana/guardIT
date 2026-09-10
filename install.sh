#!/usr/bin/env bash
# Two ways in:
#   ./install.sh                                   from a git clone — builds with cargo
#   curl -fsSL <raw url>/install.sh | bash         no clone, no cargo — grabs the latest release
set -euo pipefail

REPO="Rajaonarison-Andry-Misandratra-Fiderana/guardIT"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

if [ -f "$HERE/Cargo.toml" ]; then
    cd "$HERE"
    # `sudo ./install.sh` would build as root, whose rustup usually has no
    # toolchain — build as the user who invoked sudo instead
    if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" -H cargo build --release
    else
        cargo build --release
    fi
    cp guardit.service guardit-supervise.sh target/release/
    SRC="target/release"
else
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    URL="https://github.com/$REPO/releases/latest/download/guardit-x86_64-linux.tar.gz"
    echo "downloading $URL"
    curl -fsSL "$URL" | tar -xz -C "$TMP"
    SRC="$TMP"
fi

for tool in nft curl; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool is required but not installed." >&2
        echo "  nft  — guardit drives nftables; install the 'nftables' package" >&2
        echo "  curl — used to download the ads/tracking blocklists" >&2
        exit 1
    }
done

sudo install -Dm755 "$SRC/guardit" /usr/local/bin/guardit
sudo install -Dm755 "$SRC/guardit-supervise.sh" /usr/local/bin/guardit-supervise.sh

echo "installed: $(command -v guardit)"

# man page and shell completions, wherever the shell's completion dir exists
guardit man | sudo install -Dm644 /dev/stdin /usr/share/man/man1/guardit.1
for pair in "bash:/usr/share/bash-completion/completions/guardit" \
            "fish:/usr/share/fish/vendor_completions.d/guardit.fish" \
            "zsh:/usr/share/zsh/site-functions/_guardit"; do
    shell="${pair%%:*}"; dest="${pair#*:}"
    if [ -d "$(dirname "$dest")" ]; then
        guardit completions "$shell" | sudo install -Dm644 /dev/stdin "$dest"
    fi
done

# config moved from root's $HOME to a fixed /etc path — carry an existing one over once
if [ ! -e /etc/guardit ] && sudo test -d /root/.config/guardit; then
    sudo mv /root/.config/guardit /etc/guardit
    echo "migrated /root/.config/guardit -> /etc/guardit"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    sudo install -Dm644 "$SRC/guardit.service" /etc/systemd/system/guardit.service
    sudo systemctl daemon-reload
    # `enable --now` starts a stopped daemon but leaves a running one alone,
    # so an upgrade would install a new binary and keep serving from the old
    # one — for as long as the machine stays up. Restart it explicitly.
    if systemctl is-active --quiet guardit; then
        sudo systemctl restart guardit
        echo "daemon:    restarted on the new binary"
    else
        sudo systemctl enable --now guardit
        echo "daemon:    systemctl status guardit"
    fi
else
    echo "no systemd detected — falling back to cron for autostart"

    if ! command -v crontab >/dev/null 2>&1; then
        echo "error: cron is not installed, so guardit can't be set up to survive a reboot." >&2
        echo "install cron (e.g. cronie/fcron/bcron for your distro) and re-run this script." >&2
        exit 1
    fi

    CRON_LINE="@reboot /usr/local/bin/guardit-supervise.sh >> /var/log/guardit-supervise.log 2>&1"
    if sudo crontab -l 2>/dev/null | grep -qF "guardit-supervise.sh"; then
        echo "cron autostart entry already present"
    else
        (sudo crontab -l 2>/dev/null; echo "$CRON_LINE") | sudo crontab -
        echo "cron autostart entry added (root crontab, @reboot)"
    fi

    # also start it right now, not just on the next boot
    sudo pkill -f /usr/local/bin/guardit-supervise.sh 2>/dev/null || true
    sudo nohup /usr/local/bin/guardit-supervise.sh >/var/log/guardit-supervise.log 2>&1 &
    disown
    echo "daemon:    started via guardit-supervise.sh — tail -f /var/log/guardit-supervise.log"
fi

# Everything below is what used to be left as "now go and run these": the
# kernel ruleset, and the ads/tracking lists. An install that leaves the
# firewall unloaded and the blocklists undownloaded has not installed
# anything you can use.

# A first install picks the safe defaults; an existing one is left alone,
# including a deliberate `blocklist off`.
if ! sudo grep -q '^\[blocklist\]' /etc/guardit/rules.toml 2>/dev/null; then
    echo
    echo "setting up ads and tracking blocking (ads + phishing)"
    sudo guardit blocklist on
    # in the foreground: the daemon would fetch these within ten minutes on
    # its own, and ten minutes of "blocking is on but blocks nothing" is
    # worse than a wait you can see
    sudo guardit blocklist update || echo "warning: some lists failed — \`guardit blocklist update\` to retry"
fi

# Last, because the ruleset it generates depends on the blocklist settings
# above (the DoT/DoH rules are part of it), and because until this runs the
# kernel has none of guardit's rules at all.
echo
if sudo guardit apply; then
    echo "ruleset:   loaded into the kernel"
else
    echo "warning: could not load the ruleset — run \`sudo guardit apply\` once the cause is fixed" >&2
fi

echo
echo "done. \`sudo guardit\` for the dashboard, \`guardit blocklist categories\` for what else it can block."
# the one thing nobody discovers on their own, and the one that decides
# whether this machine spends its day asking questions
echo "       \`sudo guardit auto on\` if you would rather it decided unruled connections than asked you."
