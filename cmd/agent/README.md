# NetProbe Agent

NetProbe Agent 是一个基于 eBPF TC (Traffic Control) 的网络监控代理，能够收集网络接口的流量统计并通过 Prometheus metrics 格式暴露。

## 功能特性

- 🚀 **高性能**: 基于 eBPF TC 层的零拷贝网络监控
- 📊 **Prometheus 兼容**: 标准的 metrics 格式和 HTTP 端点
- 🔍 **多维监控**: 支持按接口、方向的详细统计
- ⚡ **实时速率**: 自动计算包速率和字节速率
- 🎯 **灵活过滤**: 支持接口过滤和活跃接口过滤
- 💪 **生产就绪**: 完善的健康检查和错误处理

## 快速开始

### 1. 构建 Agent

```bash
# 克隆仓库
git clone <repo-url>
cd netprobe

# 构建 agent
go build -o bin/netprobe-agent ./cmd/agent/

# 或使用启动脚本构建
sudo ./scripts/start_agent.sh --build-only
```

### 2. 基本运行

```bash
# 基本启动 (需要 root 权限加载 eBPF)
sudo ./bin/netprobe-agent

# 使用启动脚本
sudo ./scripts/start_agent.sh
```

### 3. 访问 Metrics

启动后可访问以下端点：
- **Metrics**: http://localhost:8081/metrics
- **健康检查**: http://localhost:8081/health
- **信息页面**: http://localhost:8081/

## 命令行选项

### 基本选项

```bash
# 自定义端口
sudo ./bin/netprobe-agent --metrics-port 9090

# 自定义收集间隔
sudo ./bin/netprobe-agent --collect-interval 3s

# 启用调试日志
sudo ./bin/netprobe-agent --debug
```

### 接口过滤

```bash
# 只监控特定接口
sudo ./bin/netprobe-agent --interface-filter eth0 --interface-filter wlan0

# 只导出活跃接口
sudo ./bin/netprobe-agent --active-only

# 组合使用
sudo ./bin/netprobe-agent --interface-filter eth0 --active-only --debug
```

### eBPF 程序附加

```bash
# 尝试自动附加 eBPF 程序到指定接口
sudo ./bin/netprobe-agent --attach-interface eth0
```

**注意**: 如果自动附加失败，需要手动使用 `tc` 命令附加程序。

## 使用启动脚本

### 基本使用

```bash
# 基本启动
sudo ./scripts/start_agent.sh

# 调试模式
sudo ./scripts/start_agent.sh --debug

# 自定义配置
sudo ./scripts/start_agent.sh --port 9090 --interval 3s --filter eth0,wlan0 --active-only
```

### 环境变量配置

```bash
# 使用环境变量
export METRICS_PORT=9090
export COLLECT_INTERVAL=3s
export INTERFACE_FILTER=eth0,wlan0
export ACTIVE_ONLY=true
export DEBUG=1

sudo ./scripts/start_agent.sh
```

## 手动 eBPF 程序附加

如果自动附加失败，可以手动附加 eBPF 程序：

```bash
# 1. 确保接口有 clsact qdisc
sudo tc qdisc add dev eth0 clsact

# 2. 编译 eBPF 程序 (如果还没有)
cd ebpf/network
go generate

# 3. 附加 TC 程序
sudo tc filter add dev eth0 ingress bpf da obj networkmonitor_bpfel_x86.o sec tc
sudo tc filter add dev eth0 egress bpf da obj networkmonitor_bpfel_x86.o sec tc

# 4. 验证附加
sudo tc filter show dev eth0 ingress
sudo tc filter show dev eth0 egress
```

## Metrics 说明

### 核心指标

| 指标名称 | 类型 | 描述 | 标签 |
|---------|------|------|------|
| `netprobe_tc_packets_total` | counter | TC 层处理的总包数 | `interface`, `ifindex`, `direction` |
| `netprobe_tc_bytes_total` | counter | TC 层处理的总字节数 | `interface`, `ifindex`, `direction` |
| `netprobe_tc_packets_per_second` | gauge | 每秒包数速率 | `interface`, `ifindex`, `direction` |
| `netprobe_tc_bytes_per_second` | gauge | 每秒字节数速率 | `interface`, `ifindex`, `direction` |
| `netprobe_interface_active` | gauge | 接口活跃状态 | `interface`, `ifindex` |

### 元数据指标

| 指标名称 | 类型 | 描述 |
|---------|------|------|
| `netprobe_up` | gauge | Agent 健康状态 |
| `netprobe_collection_total` | counter | 总收集次数 |
| `netprobe_last_collection_timestamp_seconds` | gauge | 最后收集时间戳 |

### 标签说明

- `interface`: 网络接口名称 (如 `eth0`, `wlan0`, `lo`)
- `ifindex`: 网络接口索引 (数字)
- `direction`: 流量方向 (`ingress` 或 `egress`)

## 示例 Metrics 输出

```prometheus
# HELP netprobe_tc_packets_total Total number of packets processed by TC
# TYPE netprobe_tc_packets_total counter
netprobe_tc_packets_total{direction="ingress",ifindex="2",interface="eth0"} 1543
netprobe_tc_packets_total{direction="egress",ifindex="2",interface="eth0"} 1234

# HELP netprobe_tc_bytes_total Total number of bytes processed by TC
# TYPE netprobe_tc_bytes_total counter
netprobe_tc_bytes_total{direction="ingress",ifindex="2",interface="eth0"} 98752
netprobe_tc_bytes_total{direction="egress",ifindex="2",interface="eth0"} 78976

# HELP netprobe_tc_packets_per_second Rate of packets per second processed by TC
# TYPE netprobe_tc_packets_per_second gauge
netprobe_tc_packets_per_second{direction="ingress",ifindex="2",interface="eth0"} 12.5
netprobe_tc_packets_per_second{direction="egress",ifindex="2",interface="eth0"} 9.8

# HELP netprobe_interface_active Whether the network interface is currently active
# TYPE netprobe_interface_active gauge
netprobe_interface_active{ifindex="2",interface="eth0"} 1

# HELP netprobe_up Whether the netprobe exporter is up
# TYPE netprobe_up gauge
netprobe_up 1
```

## 测试和验证

### 使用测试脚本

```bash
# 启动 agent (在另一个终端)
sudo ./bin/netprobe-agent --debug

# 运行测试脚本
./scripts/test_agent.sh

# 只测试 metrics 端点
./scripts/test_agent.sh --metrics-only

# 只测试健康检查
./scripts/test_agent.sh --health-only

# 自定义端口测试
./scripts/test_agent.sh --port 9090
```

### 手动测试

```bash
# 测试 metrics 端点
curl http://localhost:8081/metrics

# 测试健康检查
curl http://localhost:8081/health | jq

# 查看信息页面
curl http://localhost:8081/
```

### 生成测试流量

```bash
# 生成一些网络流量来测试监控
ping -c 10 google.com
wget -q -O /dev/null http://httpbin.org/bytes/1024

# 查看 metrics 变化
curl -s http://localhost:8081/metrics | grep netprobe_tc_packets_total
```

## Prometheus 集成

### Prometheus 配置

在 `prometheus.yml` 中添加：

```yaml
scrape_configs:
  - job_name: 'netprobe-agent'
    static_configs:
      - targets: ['localhost:8081']
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: /metrics
```

### Grafana 查询

```promql
# 网络流量速率
rate(netprobe_tc_bytes_total[5m])

# 包速率
rate(netprobe_tc_packets_total[5m])

# 活跃接口数量
sum(netprobe_interface_active)

# 每个接口的总流量
sum(rate(netprobe_tc_bytes_total[5m])) by (interface)

# Top 5 接口 (按字节速率)
topk(5, sum(rate(netprobe_tc_bytes_total[5m])) by (interface))
```

## 部署指南

### systemd 服务

创建 `/etc/systemd/system/netprobe-agent.service`:

```ini
[Unit]
Description=NetProbe Agent - eBPF Network Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/netprobe-agent --metrics-port 8081
Restart=always
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
```

```bash
# 启用和启动服务
sudo systemctl enable netprobe-agent
sudo systemctl start netprobe-agent
sudo systemctl status netprobe-agent
```

### Docker 部署

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o netprobe-agent ./cmd/agent/

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/netprobe-agent .
EXPOSE 8081
CMD ["./netprobe-agent"]
```

```bash
# 构建和运行
docker build -t netprobe-agent .
docker run --privileged --network host -p 8081:8081 netprobe-agent
```

### Kubernetes 部署

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: netprobe-agent
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: netprobe-agent
  template:
    metadata:
      labels:
        app: netprobe-agent
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: netprobe-agent
        image: netprobe-agent:latest
        ports:
        - containerPort: 8081
          name: metrics
        securityContext:
          privileged: true
        volumeMounts:
        - name: sys
          mountPath: /sys
          readOnly: true
        - name: proc
          mountPath: /proc
          readOnly: true
      volumes:
      - name: sys
        hostPath:
          path: /sys
      - name: proc
        hostPath:
          path: /proc
```

## 故障排除

### 常见问题

1. **eBPF 不支持**
   ```
   Error: eBPF is not supported on this system
   ```
   - 检查内核版本 (`uname -r`)
   - 确保内核编译时启用了 eBPF 支持
   - 检查是否以 root 权限运行

2. **权限不足**
   ```
   Error: failed to load network monitor: operation not permitted
   ```
   - 确保以 root 权限运行
   - 检查 CAP_SYS_ADMIN 和 CAP_NET_ADMIN 权限

3. **端口已被占用**
   ```
   Error: failed to start metrics server: bind: address already in use
   ```
   - 使用 `--metrics-port` 指定其他端口
   - 检查端口使用情况: `netstat -tlnp | grep 8081`

4. **无 TC 数据**
   ```
   Warning: 暂无 TC 相关指标数据
   ```
   - 检查是否有网络流量
   - 尝试手动附加 eBPF 程序
   - 使用 `--debug` 查看详细日志

### 调试步骤

1. **启用调试日志**
   ```bash
   sudo ./bin/netprobe-agent --debug
   ```

2. **检查 eBPF 程序加载**
   ```bash
   sudo bpftool prog list
   sudo bpftool map list
   ```

3. **检查 TC 配置**
   ```bash
   sudo tc qdisc show dev eth0
   sudo tc filter show dev eth0 ingress
   sudo tc filter show dev eth0 egress
   ```

4. **监控系统日志**
   ```bash
   sudo journalctl -f -u netprobe-agent
   dmesg | grep -i ebpf
   ```

## 性能和资源使用

### 资源消耗

- **CPU**: 通常 < 1% (取决于网络流量)
- **内存**: ~10-50MB (取决于接口数量)
- **网络**: 几乎无额外开销 (eBPF 零拷贝)

### 性能调优

```bash
# 减少收集频率以降低 CPU 使用
sudo ./bin/netprobe-agent --collect-interval 10s

# 只监控关键接口
sudo ./bin/netprobe-agent --interface-filter eth0

# 只导出活跃接口
sudo ./bin/netprobe-agent --active-only
```

## 开发和贡献

### 构建开发环境

```bash
# 安装依赖
sudo apt install clang llvm libbpf-dev

# 克隆代码
git clone <repo-url>
cd netprobe

# 运行测试
go test ./...

# 构建
go build ./cmd/agent/
```

### 添加新指标

1. 修改 eBPF 程序 (`ebpf/network/monitor.c`)
2. 更新 collector (`pkg/collector/`)
3. 添加 metrics 定义 (`pkg/metrics/`)
4. 更新测试和文档

## 许可证

[MIT License](LICENSE)
