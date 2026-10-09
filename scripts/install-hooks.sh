#!/usr/bin/env bash
# 安装 AsterTrack git hooks（一次性）
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath scripts/hooks
chmod +x scripts/hooks/pre-commit
echo "✅ hooks 已安装"
echo "   位置：scripts/hooks/pre-commit"
echo "   跳过：SKIP_HOOKS=1 git commit ...  或  git commit --no-verify"
