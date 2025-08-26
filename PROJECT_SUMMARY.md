# NetProbe 项目完整实现总结

## 项目概述

NetProbe 是一个基于 eBPF 技术的高性能网络监控系统，专注于 TC (Traffic Control) 层的网络流量统计。项目包括数据收集、指标生成和 Prometheus 兼容的 HTTP 导出功能。

## 架构组件

### 1. eBPF 层 (`ebpf/`)
- **`network/monitor.c`**: TC 层 eBPF 程序
  - 支持 XDP 和 TC hook 点
  - 收集包数、字节数、流量统计
  - 支持入站/出站流量监控
  - 使用原子操作保证线程安全

### 2. 数据收集层 (`pkg/collector/`)
- **`tc_collector.go`**: TC 层数据收集器
  - 从 eBPF maps 读取统计数据
  - 计算实时速率 (包/秒, 字节/秒)
  - 支持接口映射和过滤
- **`manager.go`**: 收集器管理器
  - 周期性数据收集
  - 错误处理和重试机制
- **`utils.go`**: 实用函数和格式化工具

### 3. 指标导出层 (`pkg/metrics/`)
- **`metrics.go`**: Prometheus 指标定义和管理
  - 符合 Prometheus 格式的指标生成
  - 支持 counter 和 gauge 类型
- **`server.go`**: HTTP 服务器
  - `/metrics` 端点 (Prometheus 格式)
  - `/health` 端点 (健康检查)
  - `/` 端点 (信息页面)
- **`exporter.go`**: 完整的导出器集成

### 4. eBPF 管理层 (`pkg/ebpf/`)
- **`manager.go`**: eBPF 程序生命周期管理
- **`network_loader.go`**: 网络监控程序加载器

### 5. 应用层 (`cmd/agent/`)
- **`main.go`**: NetProbe Agent 主程序
  - 命令行参数处理
  - eBPF 程序加载和附加
  - Metrics 导出器启动
  - 信号处理和优雅关闭

## 核心功能实现

### 1. 网络流量监控
```c
// eBPF TC 程序监控网络流量
SEC("tc")
int network_monitor_tc_ingress(struct __sk_buff *skb) {
    // 解析网络包
    // 更新统计信息
    // 返回 TC_ACT_OK
}
```

### 2. 数据收集
```go
// Go 收集器读取 eBPF 数据
func (tc *TCCollector) CollectOnce() ([]InterfaceStats, error) {
    // 读取 TC 设备统计
    // 计算速率
    // 返回接口统计数组
}
```

### 3. Prometheus 指标生成
```go
// 生成 Prometheus 格式指标
func (nm *NetworkMetrics) GetPrometheusFormat() string {
    // 按指标名称分组
    // 添加 HELP 和 TYPE 注释
    // 生成指标行
}
```

### 4. HTTP 服务
```go
// HTTP 服务器暴露指标
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
    // 设置响应头
    // 获取 Prometheus 格式指标
    // 写入响应
}
```

## 指标体系

### 核心网络指标
- `netprobe_tc_packets_total`: TC 层处理的总包数 (counter)
- `netprobe_tc_bytes_total`: TC 层处理的总字节数 (counter)
- `netprobe_tc_packets_per_second`: 每秒包数速率 (gauge)
- `netprobe_tc_bytes_per_second`: 每秒字节数速率 (gauge)
- `netprobe_interface_active`: 接口活跃状态 (gauge)

### 元数据指标
- `netprobe_up`: 导出器健康状态 (gauge)
- `netprobe_collection_total`: 总收集次数 (counter)
- `netprobe_last_collection_timestamp_seconds`: 最后收集时间戳 (gauge)

### 标签维度
- `interface`: 网络接口名称 (eth0, wlan0, lo)
- `ifindex`: 网络接口索引
- `direction`: 流量方向 (ingress, egress)

## 使用示例

### 1. 基本启动
```bash
# 构建和启动
sudo go build -o bin/netprobe-agent ./cmd/agent/
sudo ./bin/netprobe-agent
```

### 2. 自定义配置
```bash
# 自定义端口和收集间隔
sudo ./bin/netprobe-agent \
  --metrics-port 9090 \
  --collect-interval 3s \
  --interface-filter eth0 \
  --active-only \
  --debug
```

### 3. 使用启动脚本
```bash
# 使用提供的启动脚本
sudo ./scripts/start_agent.sh --debug --filter eth0,wlan0 --active-only
```

### 4. 访问指标
```bash
# 获取 Prometheus 指标
curl http://localhost:8081/metrics

# 健康检查
curl http://localhost:8081/health

# 信息页面
curl http://localhost:8081/
```

## 示例 Metrics 输出

```prometheus
# HELP netprobe_tc_packets_total Total number of packets processed by TC
# TYPE netprobe_tc_packets_total counter
netprobe_tc_packets_total{direction="ingress",ifindex="2",interface="eth0"} 15420
netprobe_tc_packets_total{direction="egress",ifindex="2",interface="eth0"} 12380

# HELP netprobe_tc_bytes_total Total number of bytes processed by TC
# TYPE netprobe_tc_bytes_total counter
netprobe_tc_bytes_total{direction="ingress",ifindex="2",interface="eth0"} 2048576
netprobe_tc_bytes_total{direction="egress",ifindex="2",interface="eth0"} 1572864

# HELP netprobe_tc_packets_per_second Rate of packets per second processed by TC
# TYPE netprobe_tc_packets_per_second gauge
netprobe_tc_packets_per_second{direction="ingress",ifindex="2",interface="eth0"} 125.5
netprobe_tc_packets_per_second{direction="egress",ifindex="2",interface="eth0"} 98.7

# HELP netprobe_interface_active Whether the network interface is currently active
# TYPE netprobe_interface_active gauge
netprobe_interface_active{ifindex="2",interface="eth0"} 1

# HELP netprobe_up Whether the netprobe exporter is up
# TYPE netprobe_up gauge
netprobe_up 1
```

## 技术特点

### 1. 高性能
- **eBPF 零拷贝**: 直接在内核空间处理网络包
- **原子操作**: 避免锁竞争，支持高并发
- **智能缓存**: 减少系统调用开销

### 2. 可观测性
- **多维度监控**: 接口、方向、协议层面的统计
- **实时速率**: 自动计算包速率和字节速率
- **健康检查**: 完善的服务状态监控

### 3. 生产就绪
- **优雅关闭**: 信号处理和资源清理
- **错误处理**: 完善的错误处理和重试机制
- **配置灵活**: 丰富的命令行选项和环境变量支持

### 4. 标准兼容
- **Prometheus 格式**: 完全符合 Prometheus metrics 规范
- **HTTP API**: 标准的 REST 端点设计
- **容器化**: 支持 Docker 和 Kubernetes 部署

## 部署和集成

### 1. Prometheus 配置
```yaml
scrape_configs:
  - job_name: 'netprobe-agent'
    static_configs:
      - targets: ['localhost:8081']
    scrape_interval: 15s
```

### 2. Grafana 查询
```promql
# 网络流量速率
rate(netprobe_tc_bytes_total[5m])

# Top 接口
topk(5, sum(rate(netprobe_tc_bytes_total[5m])) by (interface))
```

### 3. 容器部署
```bash
# Docker 运行
docker run --privileged --network host -p 8081:8081 netprobe-agent

# Kubernetes DaemonSet
kubectl apply -f deploy/agent.yaml
```

## 测试和验证

### 1. 单元测试
```bash
# 运行所有测试
go test ./pkg/collector/... -v
go test ./pkg/metrics/... -v
```

### 2. 功能测试
```bash
# 使用测试脚本
./scripts/test_agent.sh

# 手动测试
curl http://localhost:8081/metrics
```

### 3. 性能测试
```bash
# 压力测试
./scripts/test_agent.sh --performance
```

## 项目优势

### 1. 技术优势
- **现代技术栈**: eBPF + Go + Prometheus
- **高性能设计**: 零拷贝网络监控
- **云原生**: 容器化和微服务架构

### 2. 功能优势
- **实时监控**: 毫秒级数据收集
- **多维度**: 接口、方向、协议层面统计
- **标准化**: Prometheus 生态兼容

### 3. 运维优势
- **易部署**: 单二进制文件，无外部依赖
- **易监控**: 完善的健康检查和指标
- **易扩展**: 模块化设计，易于添加新功能

## 未来扩展

### 1. 功能扩展
- 添加更多网络协议支持 (IPv6, ICMP)
- 实现网络拓扑发现
- 添加安全事件监控

### 2. 性能优化
- 实现指标聚合和采样
- 优化内存使用
- 添加压缩支持

### 3. 生态集成
- 支持更多监控系统 (InfluxDB, ElasticSearch)
- 添加告警规则模板
- 集成 OpenTelemetry

## 总结

NetProbe 项目成功实现了一个完整的基于 eBPF 的网络监控系统，具备以下核心能力：

1. **高性能数据收集**: 基于 eBPF TC 层的零开销网络监控
2. **标准化指标导出**: 完全兼容 Prometheus 生态系统
3. **生产级稳定性**: 完善的错误处理、健康检查和优雅关闭
4. **灵活配置**: 丰富的命令行选项和过滤功能
5. **易于部署**: 提供完整的脚本和文档支持

该项目可以直接用于生产环境的网络监控，为运维团队提供实时、准确的网络流量可观测性。
