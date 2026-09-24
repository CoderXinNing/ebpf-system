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
        *)
            echo "未知参数: $1"; exit 1 ;;
    esac
done

# ============================================
# 检查
# ============================================
# root 检查：非 root 时自动 sudo 重试
if [[ $EUID -ne 0 ]]; then
    if command -v sudo &> /dev/null; then
        echo "🔐 需要 root 权限，自动 sudo 重试..."
        exec sudo bash "$0" "$@"
    else
        echo "❌ 请用 root 运行（sudo bash）"
        exit 1
    fi
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
# 下载 Agent 二进制
# ============================================
BIN_URL="${SERVER_URL%/}/bin/agent-linux-${BIN_ARCH}"
echo "📥 下载 Agent: $BIN_URL"

if command -v curl &> /dev/null; then
    curl -fSL -o ${INSTALL_DIR}/bin/agent "$BIN_URL"
elif command -v wget &> /dev/null; then
    wget -O ${INSTALL_DIR}/bin/agent "$BIN_URL"
else
    echo "❌ 需要 curl 或 wget"
    exit 1
fi
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
