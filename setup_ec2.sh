#!/usr/bin/env bash
# One-time setup for the Greek History World honeypot on an EC2 instance.
# Works on Amazon Linux 2023 and Ubuntu. Safe to re-run.
#
# Run on the EC2 instance, from the folder holding honeypot.py and
# site_content.py:
#
#   Bare IP, plain HTTP:       bash setup_ec2.sh
#   With your domain + HTTPS:  DOMAIN=greekhistoryworld.com EMAIL=you@example.com bash setup_ec2.sh
#
# With DOMAIN set, Caddy listens on ports 80/443, gets a free Let's Encrypt
# certificate automatically, and forwards everything to the honeypot, which
# then only listens privately on 127.0.0.1:8080. Requests to the bare IP over
# HTTP are still forwarded and logged, so you keep seeing IP-only scanners.
#
# IMPORTANT: point the domain's DNS at this server (and open port 443 in the
# security group) BEFORE running with DOMAIN, or the certificate can't be issued.
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_USER="$(whoami)"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
CADDY_VERSION="2.10.2"

echo "==> Installing Python tools"
if command -v dnf >/dev/null; then
    sudo dnf install -y python3 python3-pip tar
elif command -v apt-get >/dev/null; then
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-venv python3-pip curl tar
fi

echo "==> Creating virtual environment and installing aiohttp"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip aiohttp

if [ ! -f "$APP_DIR/stats_key.txt" ]; then
    python3 -c "import secrets; print(secrets.token_urlsafe(16))" > "$APP_DIR/stats_key.txt"
    chmod 600 "$APP_DIR/stats_key.txt"
fi
STATS_KEY="$(cat "$APP_DIR/stats_key.txt")"

if [ -n "$DOMAIN" ]; then
    HP_ARGS="--host 127.0.0.1 --port 8080 --behind-proxy --domain $DOMAIN"
    HP_CAPS=""
else
    HP_ARGS="--host 0.0.0.0 --port 80"
    HP_CAPS="AmbientCapabilities=CAP_NET_BIND_SERVICE"
fi

echo "==> Creating honeypot service"
sudo tee /etc/systemd/system/honeypot.service >/dev/null <<EOF
[Unit]
Description=Greek History World honeypot
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/honeypot.py $HP_ARGS --drip 2 --db $APP_DIR/honeypot_log.db --stats-key $STATS_KEY
$HP_CAPS
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$APP_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

if [ -n "$DOMAIN" ]; then
    echo "==> Installing Caddy $CADDY_VERSION (HTTPS front end)"
    case "$(uname -m)" in
        x86_64)  ARCH=amd64 ;;
        aarch64) ARCH=arm64 ;;
        *) echo "Unsupported CPU: $(uname -m)"; exit 1 ;;
    esac
    TMP="$(mktemp -d)"
    curl -fsSL -o "$TMP/caddy.tgz" \
        "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${ARCH}.tar.gz"
    tar -xzf "$TMP/caddy.tgz" -C "$TMP" caddy
    sudo install -m 755 "$TMP/caddy" /usr/local/bin/caddy
    rm -rf "$TMP"

    if ! id caddy >/dev/null 2>&1; then
        sudo useradd --system --create-home --home-dir /var/lib/caddy \
            --shell "$(command -v nologin || echo /sbin/nologin)" caddy
    fi

    GLOBAL=""
    [ -n "$EMAIL" ] && GLOBAL="{
	email $EMAIL
}
"
    sudo mkdir -p /etc/caddy
    sudo tee /etc/caddy/Caddyfile >/dev/null <<EOF
${GLOBAL}$DOMAIN, www.$DOMAIN {
	reverse_proxy 127.0.0.1:8080 {
		flush_interval -1
	}
}

# Plain-HTTP requests to the bare IP (scanners): forward and log them too.
:80 {
	reverse_proxy 127.0.0.1:8080 {
		flush_interval -1
	}
}
EOF

    sudo tee /etc/systemd/system/caddy.service >/dev/null <<EOF
[Unit]
Description=Caddy HTTPS front end
After=network-online.target honeypot.service
Wants=network-online.target

[Service]
User=caddy
Group=caddy
Environment=XDG_DATA_HOME=/var/lib/caddy XDG_CONFIG_HOME=/var/lib/caddy
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
else
    # Switching back to bare-IP mode: make sure Caddy isn't holding port 80.
    sudo systemctl disable --now caddy 2>/dev/null || true
fi

sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl restart honeypot
if [ -n "$DOMAIN" ]; then
    sudo systemctl enable caddy
    sudo systemctl restart caddy
fi
sleep 3
sudo systemctl --no-pager status honeypot | head -n 3
[ -n "$DOMAIN" ] && sudo systemctl --no-pager status caddy | head -n 3

PUBLIC_IP="$(curl -s https://checkip.amazonaws.com || echo '<your-public-ip>')"
echo
if [ -n "$DOMAIN" ]; then
    echo "Site:         https://$DOMAIN/   (certificate can take a minute)"
    echo "Private stats: https://$DOMAIN/stats?key=$STATS_KEY"
    echo "Caddy logs:   sudo journalctl -u caddy -f"
else
    echo "Site:         http://$PUBLIC_IP/"
    echo "Private stats: http://$PUBLIC_IP/stats?key=$STATS_KEY"
fi
echo "Honeypot log: sudo journalctl -u honeypot -f"
echo "Report:       venv/bin/python report.py honeypot_log.db"
