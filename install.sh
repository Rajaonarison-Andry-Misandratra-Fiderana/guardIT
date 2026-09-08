#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release
sudo install -Dm755 target/release/guardit /usr/local/bin/guardit
sudo install -Dm755 guardit-supervise.sh /usr/local/bin/guardit-supervise.sh

echo "installed: $(command -v guardit)"

# config moved from root's $HOME to a fixed /etc path — carry an existing one over once
if [ ! -e /etc/guardit ] && sudo test -d /root/.config/guardit; then
    sudo mv /root/.config/guardit /etc/guardit
    echo "migrated /root/.config/guardit -> /etc/guardit"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    sudo install -Dm644 guardit.service /etc/systemd/system/guardit.service
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
