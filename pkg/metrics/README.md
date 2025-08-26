# NetProbe Metrics Exporter

NetProbe Metrics Exporter 是一个 Prometheus 兼容的网络流量指标导出器，基于 eBPF TC (Traffic Control) 层数据收集。它提供了一个 HTTP 服务器来暴露网络接口的流量统计信息。

## 特性

- **Prometheus 兼容**: 完全符合 Prometheus metrics 格式
- **实时网络监控**: 基于 eBPF TC 层的高性能数据收集
- **多维度指标**: 包括包数、字节数、速率等多种指标
- **接口级监控**: 为每个网络接口提供独立的统计
- **HTTP API**: 标准的 `/metrics` 端点和健康检查
- **灵活配置**: 支持自定义端口、路径、收集间隔等
- **过滤功能**: 支持接口过滤和活跃接口过滤

## 快速开始

### 基本使用

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/your-org/kube-net-probe/pkg/ebpf"
    "github.com/your-org/kube-net-probe/pkg/metrics"
)

func main() {
    // 1. 创建 eBPF 管理器
    ebpfManager := ebpf.NewManager()
    
    // 2. 加载网络监控程序
    if err := ebpfManager.LoadNetworkMonitor(); err != nil {
        log.Fatalf("Failed to load network monitor: %v", err)
    }
    defer ebpfManager.Close()
    
    // 3. 创建 metrics 导出器
    exporter := metrics.NewExporter(ebpfManager, nil)
    
    // 4. 启动导出器
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()
    
    if err := exporter.Start(ctx); err != nil {
        log.Fatalf("Failed to start exporter: %v", err)
    }
    defer exporter.Stop()
    
    // 5. 等待上下文结束
    <-ctx.Done()
    log.Println("Exporter stopped")
}
```

启动后访问：
- Metrics: http://localhost:8081/metrics
- Health: http://localhost:8081/health
- Info: http://localhost:8081/

### 自定义配置

```go
config := &metrics.ExporterConfig{
    ServerConfig: &metrics.ServerConfig{
        Port:         9090,           // 自定义端口
        Path:         "/metrics",     // metrics 路径
        EnableCORS:   true,          // 启用 CORS
        EnableGzip:   true,          // 启用 Gzip
    },
    CollectInterval:  3 * time.Second,                    // 收集间隔
    InterfaceFilter: []string{"eth0", "wlan0"},          // 接口过滤
    EnableActiveOnly: true,                              // 只导出活跃接口
    LogLevel:        "debug",                            // 日志级别
}

exporter := metrics.NewExporter(ebpfManager, config)
```

## 指标说明

### 核心指标

| 指标名称 | 类型 | 描述 | 标签 |
|---------|------|------|------|
| `netprobe_tc_packets_total` | counter | TC 层处理的总包数 | `interface`, `ifindex`, `direction` |
| `netprobe_tc_bytes_total` | counter | TC 层处理的总字节数 | `interface`, `ifindex`, `direction` |
| `netprobe_tc_packets_per_second` | gauge | 每秒包数速率 | `interface`, `ifindex`, `direction` |
| `netprobe_tc_bytes_per_second` | gauge | 每秒字节数速率 | `interface`, `ifindex`, `direction` |
| `netprobe_interface_active` | gauge | 接口活跃状态 (1=活跃, 0=非活跃) | `interface`, `ifindex` |

### 元数据指标

| 指标名称 | 类型 | 描述 |
|---------|------|------|
| `netprobe_up` | gauge | 导出器健康状态 (1=正常, 0=异常) |
| `netprobe_collection_total` | counter | 总收集次数 |
| `netprobe_last_collection_timestamp_seconds` | gauge | 最后收集时间戳 |

### 标签说明

- `interface`: 网络接口名称 (如 `eth0`, `wlan0`)
- `ifindex`: 网络接口索引 (数字)
- `direction`: 流量方向 (`ingress` 或 `egress`)

## 示例输出

```prometheus
# HELP netprobe_tc_packets_total Total number of packets processed by TC
# TYPE netprobe_tc_packets_total counter
netprobe_tc_packets_total{direction="ingress",ifindex="2",interface="eth0"} 15420.000000
netprobe_tc_packets_total{direction="egress",ifindex="2",interface="eth0"} 12380.000000

# HELP netprobe_tc_bytes_total Total number of bytes processed by TC
# TYPE netprobe_tc_bytes_total counter
netprobe_tc_bytes_total{direction="ingress",ifindex="2",interface="eth0"} 2048576.000000
netprobe_tc_bytes_total{direction="egress",ifindex="2",interface="eth0"} 1572864.000000

# HELP netprobe_tc_packets_per_second Rate of packets per second processed by TC
# TYPE netprobe_tc_packets_per_second gauge
netprobe_tc_packets_per_second{direction="ingress",ifindex="2",interface="eth0"} 125.500000
netprobe_tc_packets_per_second{direction="egress",ifindex="2",interface="eth0"} 98.700000

# HELP netprobe_tc_bytes_per_second Rate of bytes per second processed by TC
# TYPE netprobe_tc_bytes_per_second gauge
netprobe_tc_bytes_per_second{direction="ingress",ifindex="2",interface="eth0"} 16384.200000
netprobe_tc_bytes_per_second{direction="egress",ifindex="2",interface="eth0"} 12582.900000

# HELP netprobe_interface_active Whether the network interface is currently active
# TYPE netprobe_interface_active gauge
netprobe_interface_active{ifindex="2",interface="eth0"} 1.000000

# HELP netprobe_up Whether the netprobe exporter is up
# TYPE netprobe_up gauge
netprobe_up 1.000000
```

## HTTP 端点

### `/metrics`
标准的 Prometheus metrics 端点，返回所有网络指标。

**响应格式**: `text/plain; version=0.0.4; charset=utf-8`

### `/health`
健康检查端点，返回 JSON 格式的服务状态。

**响应示例**:
```json
{
  "status": "ok",
  "timestamp": "2023-12-07T10:30:00Z",
  "server": {
    "running": true,
    "port": 8081,
    "requests": 42,
    "metrics": 16,
    "collections": 8,
    "last_collection": "2023-12-07T10:29:55Z"
  }
}
```

### `/`
信息页面，提供导出器概览和端点链接。

## 配置选项

### ServerConfig

```go
type ServerConfig struct {
    Port            int           // 监听端口，默认 8081
    Path            string        // metrics 路径，默认 "/metrics"
    ReadTimeout     time.Duration // 读取超时，默认 10 秒
    WriteTimeout    time.Duration // 写入超时，默认 10 秒
    MaxHeaderBytes  int           // 最大头部字节数，默认 1MB
    EnableCORS      bool          // 是否启用 CORS，默认 true
    EnableGzip      bool          // 是否启用 Gzip，默认 true
}
```

### ExporterConfig

```go
type ExporterConfig struct {
    ServerConfig     *ServerConfig  // 服务器配置
    CollectInterval  time.Duration  // 数据收集间隔，默认 5 秒
    InterfaceFilter  []string       // 接口名称过滤器，空表示所有接口
    EnableActiveOnly bool           // 是否只导出活跃接口的指标
    LogLevel        string         // 日志级别：debug, info, warn, error
}
```

## Prometheus 配置

在 `prometheus.yml` 中添加以下配置：

```yaml
scrape_configs:
  - job_name: 'netprobe'
    static_configs:
      - targets: ['localhost:8081']
    scrape_interval: 15s
    metrics_path: /metrics
```

## Grafana 仪表板

### 推荐查询

**网络接口流量速率**:
```promql
rate(netprobe_tc_bytes_total[5m])
```

**活跃接口数量**:
```promql
sum(netprobe_interface_active)
```

**总网络流量**:
```promql
sum(rate(netprobe_tc_bytes_total[5m])) by (direction)
```

**接口包速率 Top 5**:
```promql
topk(5, sum(rate(netprobe_tc_packets_total[5m])) by (interface))
```

### 示例面板

1. **网络流量概览**: 显示总的入站/出站流量
2. **接口详情**: 每个接口的详细统计
3. **速率趋势**: 包速率和字节速率的时间序列
4. **活跃接口**: 当前活跃的网络接口列表

## 性能特性

- **低延迟**: 基于 eBPF 的数据收集，微秒级延迟
- **高效率**: 原子操作，无锁设计
- **可扩展**: 支持大量网络接口
- **内存友好**: 智能缓存和数据压缩

## 故障排除

### 常见问题

1. **No metrics available**
   - 检查 eBPF 程序是否正确加载
   - 确认网络接口有流量
   - 检查接口过滤配置

2. **Collection errors**
   - 验证 eBPF 程序权限
   - 检查内核版本兼容性
   - 查看系统日志

3. **High error rate**
   - 调整收集间隔
   - 检查系统资源使用情况
   - 验证网络接口状态

### 调试模式

启用调试日志：
```go
config := &metrics.ExporterConfig{
    LogLevel: "debug",
}
```

### 健康检查

监控 `/health` 端点，确保：
- `status` 为 `ok`
- `last_collection` 时间不超过 30 秒
- `collections` 计数在增长

## 集成示例

### Docker 部署

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o netprobe-exporter ./cmd/exporter

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/netprobe-exporter .
EXPOSE 8081
CMD ["./netprobe-exporter"]
```

### Kubernetes 部署

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: netprobe-exporter
spec:
  selector:
    matchLabels:
      app: netprobe-exporter
  template:
    metadata:
      labels:
        app: netprobe-exporter
    spec:
      hostNetwork: true
      containers:
      - name: netprobe-exporter
        image: netprobe-exporter:latest
        ports:
        - containerPort: 8081
          name: metrics
        securityContext:
          privileged: true
```

## 开发和测试

### 运行测试

```bash
go test ./pkg/metrics/... -v
```

### 基准测试

```bash
go test ./pkg/metrics/... -bench=. -benchmem
```

### 示例程序

```bash
# 运行简单示例
go run ./pkg/metrics/examples.go

# 运行自定义配置示例  
go run ./pkg/metrics/examples.go -config custom
```
