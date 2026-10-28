#!/usr/bin/env bash
# setup_ec2.sh — Run once on the EC2 Ubuntu instance as your IAM user (with sudo).
# Sets up: Python 3.12, the auditor user and service, and the agent systemd unit.
# Usage: bash scripts/setup_ec2.sh <S3_BUCKET_NAME>
set -euo pipefail

BUCKET="${1:?usage: $0 <s3-bucket-name>}"
INSTALL_DIR="/opt/linux-server-auditor"
SERVICE_USER="auditor"
PYTHON="python3.12"

echo "==> Installing system dependencies"
apt-get update -qq
apt-get install -y -qq python3.12 python3.12-venv python3-pip git curl

echo "==> Creating service user: $SERVICE_USER"
id "$SERVICE_USER" &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"

echo "==> Deploying code to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo "==> Creating Python venv and installing deps"
sudo -u "$SERVICE_USER" "$PYTHON" -m venv "$INSTALL_DIR/.venv"
sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install -q --upgrade pip
sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install -q -e "$INSTALL_DIR[dev]" 2>/dev/null || \
  sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install -q \
    boto3 psutil pyyaml

echo "==> Patching config/settings.yaml with bucket name"
INSTANCE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $(curl -sf -X PUT \
  'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" \
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
ExecStart=$INSTALL_DIR/.venv/bin/python -m linux_server_auditor agent
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR/data

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable linux-server-auditor
systemctl start linux-server-auditor

echo "==> Done. Status:"
systemctl status linux-server-auditor --no-pager
