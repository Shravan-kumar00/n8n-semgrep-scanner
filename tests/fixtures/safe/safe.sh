#!/bin/bash
set -euo pipefail
DB_PASSWORD="${DB_PASSWORD:?missing}"
TOKEN=$(cat /run/secrets/token)
curl -fsSL https://example.com/tool.tgz -o tool.tgz
sha256sum -c tool.tgz.sha256
chmod 750 /opt/app
