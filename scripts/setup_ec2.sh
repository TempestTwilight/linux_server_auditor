#!/usr/bin/env bash
# setup_ec2.sh — Run once on the EC2 Ubuntu instance as your IAM user (with sudo).
# Sets up: uv, Python 3.14.0, the auditor user and service, and the agent systemd unit.
# Usage: bash scripts/setup_ec2.sh <S3_BUCKET_NAME>
set -euo pipefail

BUCKET="${1:?usage: $0 <s3-bucket-name>}"
INSTALL_DIR="/opt/linux-server-auditor"
SERVICE_USER="auditor"

echo "==> Installing uv"
apt-get update -qq
apt-get install -y -qq curl git
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

echo "==> Creating service user: $SERVICE_USER"
id "$SERVICE_USER" &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"

echo "==> Deploying code to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo "==> Installing Python and deps via uv"
# uv reads .python-version (3.14.0) and pyproject.toml automatically
sudo -u "$SERVICE_USER" bash -c "
  export PATH=/root/.local/bin:\$HOME/.local/bin:\$PATH
  cd $INSTALL_DIR
  uv python install
  uv sync --no-dev
"

echo "==> Patching config/settings.yaml with bucket and instance ID"
TOKEN=$(curl -sf -X PUT 'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
INSTANCE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id)
sed -i "s|bucket: null|bucket: $BUCKET|" "$INSTALL_DIR/config/settings.yaml"
sed -i "s|instance_id: null|instance_id: $INSTANCE_ID|" "$INSTALL_DIR/config/settings.yaml"

echo "==> Creating systemd service unit"
cat > /etc/systemd/system/linux-server-auditor.service << EOF
[Unit]
Description=Linux Server Health and Security Auditor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/root/.local/bin/uv run --project $INSTALL_DIR linux-server-auditor agent
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR/data
Environment=PATH=/root/.local/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable linux-server-auditor
systemctl start linux-server-auditor

echo "==> Done. Status:"
systemctl status linux-server-auditor --no-pager
