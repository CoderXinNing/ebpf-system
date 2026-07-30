#!/bin/bash
set -e

VERSION="1.0.0"
INSTALL_DIR="/opt/ebpf-sentinel"
CONFIG_DIR="${INSTALL_DIR}/configs"
BIN_DIR="${INSTALL_DIR}/bin"
PROBES_DIR="${INSTALL_DIR}/probes"

# 默认参数
SERVER="127.0.0.1:50051"
GROUP="默认组"
RUN_AS="root"
OS="linux-amd64"

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER="$2"; shift 2 ;;
        --group)  GROUP="$2"; shift 2 ;;
        --run-as) RUN_AS="$2"; shift 2 ;;
        --os)     OS="$2"; shift 2 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

echo "╔══════════════════════════════════════╗"
echo "║  eBPF Sentinel Agent v${VERSION}          ║"
echo "╠══════════════════════════════════════╣"
echo "║  业务组: ${GROUP}                         ║"
echo "║  运行用户: ${RUN_AS}                      ║"
echo "║  Server: ${SERVER}              ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 创建目录
mkdir -p ${INSTALL_DIR} ${CONFIG_DIR} ${BIN_DIR} ${PROBES_DIR}

# 复制Agent二进制（从安装包同目录）
AGENT_BIN="${BIN_DIR}/agent"
if [ -f "./agent-linux-${OS##*-}" ]; then
    cp "./agent-linux-${OS##*-}" ${AGENT_BIN}
else
    echo "❌ 找不到 agent-linux-${OS##*-}，请确认架构"
    exit 1
fi
chmod +x ${AGENT_BIN}

# 生成配置文件
HOSTNAME=$(hostname)
cat > ${CONFIG_DIR}/agent.yaml << YAML
agent:
    name: "${HOSTNAME}"
    server: "${SERVER}"
    retry_delay: 5s
    heartbeat_interval: 10s

autoload: []

collect_interval: 300s
YAML

echo "📝 配置已生成: ${CONFIG_DIR}/agent.yaml"

# 创建systemd服务
if [ "${RUN_AS}" != "root" ]; then
    RUN_CMD="${BIN_DIR}/agent --config ${CONFIG_DIR}/agent.yaml"
else
    RUN_CMD="${BIN_DIR}/agent --config ${CONFIG_DIR}/agent.yaml"
fi

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
    echo ""
    echo "✅ Agent 安装成功并已启动！"
else
    echo ""
    echo "⚠️  Agent 启动失败，查看日志: journalctl -u ebpf-sentinel-agent -n 20"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  目录:    ${INSTALL_DIR}"
echo "  配置:    ${CONFIG_DIR}/agent.yaml"
echo "  日志:    journalctl -u ebpf-sentinel-agent -f"
echo "  状态:    systemctl status ebpf-sentinel-agent"
echo "  停止:    systemctl stop ebpf-sentinel-agent"
echo "  重启:    systemctl restart ebpf-sentinel-agent"
echo "  卸载:    ${INSTALL_DIR}/uninstall.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 生成卸载脚本
cat > ${INSTALL_DIR}/uninstall.sh << 'UNINSTALL'
#!/bin/bash
echo "🗑️  卸载 eBPF Sentinel Agent..."
systemctl stop ebpf-sentinel-agent 2>/dev/null
systemctl disable ebpf-sentinel-agent 2>/dev/null
rm -f /etc/systemd/system/ebpf-sentinel-agent.service
systemctl daemon-reload
rm -rf /opt/ebpf-sentinel
echo "✅ 已卸载"
UNINSTALL
chmod +x ${INSTALL_DIR}/uninstall.sh
