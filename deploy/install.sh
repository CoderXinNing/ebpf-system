#!/bin/bash
set -e

VERSION="1.0.0"
INSTALL_DIR="/opt/ebpf-sentinel"
CONFIG_DIR="${INSTALL_DIR}/configs"
BIN_DIR="${INSTALL_DIR}/bin"
PROBES_DIR="${INSTALL_DIR}/probes"

SERVER="127.0.0.1:50051"
GROUP="默认组"
RUN_AS="root"
OS="linux-amd64"

while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER="$2"; shift 2 ;;
        --group)  GROUP="$2"; shift 2 ;;
        --run-as) RUN_AS="$2"; shift 2 ;;
        --os)     OS="$2"; shift 2 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

# 从SERVER提取HTTP地址
HTTP_SERVER=$(echo $SERVER | sed 's/:50051//')

echo "╔══════════════════════════════════════╗"
echo "║  eBPF Sentinel Agent v${VERSION}          ║"
echo "║  业务组: ${GROUP}                         ║"
echo "║  Server: ${SERVER}              ║"
echo "╚══════════════════════════════════════╝"

mkdir -p ${INSTALL_DIR} ${CONFIG_DIR} ${BIN_DIR} ${PROBES_DIR}

# 从Server下载Agent二进制
AGENT_URL="http://${HTTP_SERVER}:8080/bin/agent-linux-${OS##*-}"
echo "📥 下载 ${AGENT_URL}..."
if command -v curl &> /dev/null; then
    curl -fSL -o ${BIN_DIR}/agent "${AGENT_URL}"
elif command -v wget &> /dev/null; then
    wget -O ${BIN_DIR}/agent "${AGENT_URL}"
else
    echo "❌ 需要 curl 或 wget"
    exit 1
fi
chmod +x ${BIN_DIR}/agent

# 生成配置
cat > ${CONFIG_DIR}/agent.yaml << YAML
agent:
    name: "$(hostname)"
    server: "${SERVER}"
    retry_delay: 5s
    heartbeat_interval: 10s
    group: "${GROUP}"

autoload: []
collect_interval: 300s
YAML

# systemd服务
cat > /etc/systemd/system/ebpf-sentinel-agent.service << SYSTEMD
[Unit]
Description=eBPF Sentinel Agent
After=network.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/agent --config ${CONFIG_DIR}/agent.yaml
Restart=always
RestartSec=10
User=${RUN_AS}

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable ebpf-sentinel-agent
systemctl start ebpf-sentinel-agent

sleep 2

if systemctl is-active --quiet ebpf-sentinel-agent; then
    echo "✅ Agent 安装成功！"
else
    echo "⚠️  启动失败: journalctl -u ebpf-sentinel-agent -n 10"
fi
