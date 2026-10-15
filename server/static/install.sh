#!/bin/bash
#
# AsterTrack Agent 安装脚本
#
# 用法（Dev / LAN）：
#   curl -sSL http://<server>:8080/install.sh | sudo bash -s -- \
#     --server=http://<server>:8080 \
#     --token=ATK-xxxx
#
# 参数：
#   --server       Server URL（如 http://172.16.2.145:8080）
#   --token        注册 Token（ATK-xxx）
#   --install-dir  安装目录（默认 /opt/astertrack）
#   --hostname     主机名（默认自动获取）
#

set -e

# ============================================
# 默认参数
# ============================================
SERVER_URL=""
TOKEN=""
INSTALL_DIR="/opt/astertrack"
HOSTNAME_ARG=""
BIN_URL=""
ALLOW_HTTP=0

# ============================================
# 解析参数
# ============================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --server=*)
            SERVER_URL="${1#*=}"; shift ;;
        --server)
            SERVER_URL="$2"; shift 2 ;;
        --token=*)
            TOKEN="${1#*=}"; shift ;;
        --token)
            TOKEN="$2"; shift 2 ;;
        --install-dir=*)
            INSTALL_DIR="${1#*=}"; shift ;;
        --install-dir)
            INSTALL_DIR="$2"; shift 2 ;;
        --hostname=*)
            HOSTNAME_ARG="${1#*=}"; shift ;;
        --hostname)
            HOSTNAME_ARG="$2"; shift 2 ;;
        --allow-http)
            ALLOW_HTTP=1; shift ;;
        *)
            echo "未知参数: $1"; exit 1 ;;
    esac
done

# ============================================
# 检查
# ============================================
# ============================================
# root 权限检查
# ============================================
# 三种安装方式：
#   1. Server 接管：命令由 root 通道注入，设 SKIP_SUDO_CHECK=1 跳过
#   2. 一键安装：curl | bash —— 管道场景，提示手动加 sudo（不自动提权）
#   3. 手动下载：本地文件 —— 自动 sudo 重试，体验友好
if [[ $EUID -ne 0 ]]; then
    # 场景 1：Server 接管，调用方声明"已在 root 环境"
    if [[ "${SKIP_SUDO_CHECK:-0}" == "1" ]]; then
        echo "❌ SKIP_SUDO_CHECK=1 但当前非 root，无法继续"
        exit 1
    fi

    if ! command -v sudo &> /dev/null; then
        echo "❌ 需要 root 权限，且系统未安装 sudo"
        exit 1
    fi

    # 场景 2：管道运行（$0 为 bash/-bash）—— 提示手动 sudo，不自动提权
    if [[ "$0" == "bash" || "$0" == "-bash" ]]; then
        echo "❌ 通过管道运行时需显式 sudo（安全考虑，不自动提权）："
        echo ""
        echo "   curl -sSL http://<server>:8080/install.sh | sudo bash -s -- \\"
        echo "     --server=http://<server>:8080 \\"
        echo "     --token=ATK-xxxx"
        echo ""
        echo "   或先下载再执行："
        echo "   curl -sSL http://<server>:8080/install.sh -o install.sh"
        echo "   sudo bash install.sh --server=... --token=..."
        exit 1
    fi

    # 场景 3：本地文件 —— 自动 sudo 重试
    echo "🔐 需要 root 权限，自动 sudo 重试..."
    exec sudo bash "$0" "$@"
fi

if [[ -z "$SERVER_URL" ]] || [[ -z "$TOKEN" ]]; then
    echo "❌ 缺少参数"
    echo "用法:"
    echo "  curl -sSL http://<server>:8080/install.sh | sudo bash -s -- \\"
    echo "    --server=http://<server>:8080 \\"
    echo "    --token=ATK-xxxx"
    exit 1
fi

# ============================================
# 打印信息
# ============================================
echo "╔════════════════════════════════════════╗"
echo "║  AsterTrack Agent Installer            ║"
echo "║  Version 1.0.0                         ║"
echo "╠════════════════════════════════════════╣"
echo "║  Server:  ${SERVER_URL}"
echo "║  安装目录: ${INSTALL_DIR}"
echo "╚════════════════════════════════════════╝"
echo ""

# ============================================
# 检测架构
# ============================================
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        BIN_ARCH="amd64" ;;
    aarch64|arm64)
        BIN_ARCH="arm64" ;;
    *)
        echo "❌ 不支持的架构: $ARCH"
        exit 1 ;;
esac
echo "🔍 架构: $ARCH ($BIN_ARCH)"

# ============================================
# 创建目录
# ============================================
mkdir -p ${INSTALL_DIR}/bin
mkdir -p ${INSTALL_DIR}/certs
mkdir -p ${INSTALL_DIR}/data

# ============================================
# HTTPS 检查（BUG-012）
# ============================================
if [[ "$SERVER_URL" != https://* ]]; then
    if [[ "$ALLOW_HTTP" != "1" ]]; then
        echo "❌ SERVER_URL 必须为 HTTPS"
        echo "   如确需在可信 LAN 使用 HTTP，加 --allow-http"
        exit 1
    fi
    echo "⚠️  警告：使用 HTTP（非加密通道）"
    echo "    token 和 Agent 二进制可能被中间人截获/替换"
    echo ""
fi

# ============================================
# 下载 Agent 二进制 + SHA256 完整性校验（BUG-012）
# ============================================
BIN_URL="${SERVER_URL%/}/bin/agent-linux-${BIN_ARCH}"
SHA_URL="${BIN_URL}.sha256"

# 1. 先取期望 SHA256
EXPECTED_SHA=""
if command -v curl &> /dev/null; then
    EXPECTED_SHA=$(curl -fsSL "$SHA_URL" 2>/dev/null | awk '{print $1}')
elif command -v wget &> /dev/null; then
    EXPECTED_SHA=$(wget -qO- "$SHA_URL" 2>/dev/null | awk '{print $1}')
fi

if [[ -z "$EXPECTED_SHA" ]] || [[ ${#EXPECTED_SHA} -ne 64 ]]; then
    echo "❌ 无法获取有效 SHA256: $SHA_URL"
    echo "   拒绝在无完整性校验的情况下安装"
    exit 1
fi

# 2. 下载二进制
echo "📥 下载 Agent: $BIN_URL"
if command -v curl &> /dev/null; then
    curl -fSL -o ${INSTALL_DIR}/bin/agent "$BIN_URL"
elif command -v wget &> /dev/null; then
    wget -O ${INSTALL_DIR}/bin/agent "$BIN_URL"
else
    echo "❌ 需要 curl 或 wget"
    exit 1
fi

# 3. 校验
if ! command -v sha256sum &> /dev/null; then
    echo "❌ 系统缺少 sha256sum，无法校验"
    rm -f ${INSTALL_DIR}/bin/agent
    exit 1
fi
ACTUAL_SHA=$(sha256sum ${INSTALL_DIR}/bin/agent | awk '{print $1}')
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
    echo "❌ SHA256 校验失败"
    echo "   期望: $EXPECTED_SHA"
    echo "   实际: $ACTUAL_SHA"
    rm -f ${INSTALL_DIR}/bin/agent
    exit 1
fi
echo "✅ SHA256 校验通过"

chmod +x ${INSTALL_DIR}/bin/agent

# ============================================
# Enrollment
# ============================================
echo ""
echo "🔧 执行 Enrollment..."

ENROLL_ARGS="--server=$SERVER_URL --token=$TOKEN --install-dir=$INSTALL_DIR"
if [[ -n "$HOSTNAME_ARG" ]]; then
    ENROLL_ARGS="$ENROLL_ARGS --hostname=$HOSTNAME_ARG"
fi

${INSTALL_DIR}/bin/agent enroll $ENROLL_ARGS

if [[ ! -f ${INSTALL_DIR}/agent.toml ]]; then
    echo "❌ Enrollment 失败：未生成 agent.toml"
    exit 1
fi

# ============================================
# 安装 systemd 服务
# ============================================
echo ""
echo "🔧 安装 systemd 服务..."

cat > /etc/systemd/system/aster-track-agent.service << SYSTEMD
[Unit]
Description=AsterTrack Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/agent --config ${INSTALL_DIR}/agent.toml
Restart=always
RestartSec=10
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable aster-track-agent

# ============================================
# 启动服务
# ============================================
echo ""
echo "🚀 启动 Agent..."
systemctl start aster-track-agent

sleep 3

# ============================================
# 验证
# ============================================
if systemctl is-active --quiet aster-track-agent; then
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║  ✅ AsterTrack Agent 安装成功          ║"
    echo "╠════════════════════════════════════════╣"
    echo "║  查看状态:  systemctl status aster-track-agent"
    echo "║  查看日志:  journalctl -u aster-track-agent -f"
    echo "║  停止服务:  systemctl stop aster-track-agent"
    echo "╚════════════════════════════════════════╝"
else
    echo ""
    echo "⚠️ 服务启动失败"
    echo "   查看日志: journalctl -u aster-track-agent -n 50"
    exit 1
fi
