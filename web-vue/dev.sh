#!/bin/bash
# 启动前端 dev server（自动切 node 20）
set -e

export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20 --silent 2>/dev/null || true

cd "$(dirname "$0")"
exec npm run dev -- "$@"
