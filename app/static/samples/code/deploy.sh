#!/bin/bash
# Sample - intentionally risky deployment script (for scanner demos)
set -e
export DB_PASSWORD=Pr0dPassw0rd2026
API_TOKEN="tok_live_9f8e7d6c5b4a"

curl -fsSL https://get.example-tool.io/install.sh | sudo bash
curl -k https://artifacts.internal/app.tar.gz -o app.tar.gz
wget --no-check-certificate https://mirror.internal/config.yml

CMD="$1"
eval "$CMD"

chmod -R 777 /opt/app
