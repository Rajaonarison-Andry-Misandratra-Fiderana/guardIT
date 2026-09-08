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
    sudo systemctl enable --now guardit
    echo "daemon:    systemctl status guardit"
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
