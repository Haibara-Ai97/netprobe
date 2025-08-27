# NetProbe - 高性能 eBPF 网络监控系统

## 🎯 项目概述

NetProbe 是一个基于 **Cilium/eBPF** 库实现的云原生网络监控系统，专为 Kubernetes 环境设计。它利用 eBPF 技术在内核空间进行高效的网络数据包处理，提供实时、低开销的网络流量监控和安全分析。

## ✨ 核心特性

### 🚀 高性能监控
- **零拷贝处理**：基于 eBPF 的内核级数据包处理
- **多层监控**：支持 XDP、TC (Traffic Control) 和 Socket 层监控
- **实时统计**：毫秒级网络流量统计和异常检测

### 🔒 安全分析
- **端口扫描检测**：识别异常端口扫描行为
- **异常连接监控**：检测可疑网络连接模式
- **DDoS 防护**：实时流量分析和攻击检测

### 🎛️ 云原生设计
- **Kubernetes 集成**：原生支持容器网络监控
- **Prometheus 兼容**：标准 metrics 格式导出
- **容器感知**：Pod 和 Service 级别的网络可视化

### � 开发友好
- **纯 Go 实现**：使用 cilium/ebpf 库，无需 CGO
- **类型安全**：编译时错误检查，避免运行时问题
- **事件驱动**：基于 Ring Buffer 的高效事件处理系统

## 📁 系统架构

### 核心组件架构
```
┌─────────────────────────────────────────────────────────────────┐
│                        用户空间 (User Space)                      │
├─────────────────────────────────────────────────────────────────┤
│  cmd/agent/           │  pkg/metrics/        │  pkg/collector/   │
│  ┌─────────────────┐   │  ┌─────────────────┐  │  ┌──────────────┐ │
│  │   NetProbe      │   │  │   Prometheus    │  │  │ TC Collector │ │
│  │   Agent         │◄──┤  │   Metrics       │◄─┤  │              │ │
│  │                 │   │  │   Server        │  │  │              │ │
│  └─────────────────┘   │  └─────────────────┘  │  └──────────────┘ │
│           │            │           │           │         ▲        │
│           ▼            │           ▼           │         │        │
│  ┌─────────────────────┴─────────────────────┐ │         │        │
│  │            pkg/ebpf/manager.go             │ │         │        │
│  │          (eBPF 程序生命周期管理)            │ │         │        │
│  └─────────────────────┬─────────────────────┘ │         │        │
├─────────────────────────┼─────────────────────────────────┼────────┤
│                        ▼                               │        │
│                   内核空间 (Kernel Space)                │        │
├─────────────────────────────────────────────────────────┼────────┤
│  ebpf/network/monitor.c                               │        │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────┼────┐   │
│  │   XDP Hook      │ │   TC Ingress    │ │ TC Egress   │    │   │
│  │                 │ │   Hook          │ │ Hook        │    │   │
│  │ 网卡驱动层拦截   │ │                 │ │             │    │   │
│  └─────────────────┘ └─────────────────┘ └─────────────┼────┘   │
│           │                   │                   │    │        │
│           ▼                   ▼                   ▼    ▼        │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    eBPF Maps                              │ │
│  │  packet_stats │ flow_stats │ tc_device_stats              │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 数据流向
1. **数据包捕获**：eBPF 程序在 XDP/TC 层拦截网络数据包
2. **统计更新**：使用原子操作更新 eBPF Maps 中的统计数据
3. **数据收集**：Go 收集器定期读取 eBPF Maps 数据
4. **指标计算**：计算实时速率和聚合统计信息
5. **指标导出**：通过 Prometheus 格式 HTTP 接口暴露指标

## 🚀 快速开始

### 1. 环境要求

- **操作系统**：Linux 内核 4.18+ (推荐 5.4+)
- **开发环境**：Go 1.21+
- **权限要求**：Root 权限（用于加载 eBPF 程序）
- **依赖工具**：clang, llvm, libbpf

### 2. 编译安装

```bash
# 克隆项目
git clone https://github.com/Haibara-Ai97/netprobe.git
cd netprobe

# 安装 Go 依赖
go mod tidy

# 编译 eBPF 程序
make build-ebpf

# 编译 NetProbe Agent
make build

# 或者使用脚本一键编译
./scripts/build_ebpf.sh
```

### 3. 运行监控

```bash
# 启动 NetProbe Agent (需要 root 权限)
sudo ./bin/netprobe-agent \
  --metrics-port=8081 \
  --collect-interval=5s \
  --interface-filter=eth0,wlan0

# 查看监控指标
curl http://localhost:8081/metrics

# 指定网络接口监控
sudo NETWORK_INTERFACE=eth0 ./bin/netprobe-agent
```

### 4. Kubernetes 部署

```bash
# 部署到 Kubernetes 集群
kubectl apply -f deploy/agent.yaml

# 查看 Pod 状态
kubectl get pods -l app=netprobe-agent

# 查看监控数据
kubectl port-forward service/netprobe-metrics 8081:8081
curl http://localhost:8081/metrics
```

## 🔧 核心 API 与使用

### eBPF 管理器

```go
import "github.com/Haibara-Ai97/netprobe/pkg/ebpf"

// 创建 eBPF 管理器
manager, err := ebpf.NewManager()
if err != nil {
    return err
}
defer manager.Close()

// 附加网络监控程序到接口
err = manager.AttachNetworkMonitor("eth0")
if err != nil {
    return err
}

// 获取网络统计
stats, err := manager.GetNetworkStats()
if err != nil {
    return err
}
```

### 数据收集器

```go
import "github.com/Haibara-Ai97/netprobe/pkg/collector"

// 创建 TC 收集器
collector := collector.NewTCCollector(manager)

// 设置收集间隔
collector.SetCollectInterval(5 * time.Second)

// 执行一次数据收集
interfaceStats, err := collector.CollectOnce()
if err != nil {
    return err
}

// 打印接口统计
for _, stats := range interfaceStats {
    fmt.Printf("Interface %s: RX %d packets, TX %d packets\n", 
        stats.InterfaceName, stats.IngressPackets, stats.EgressPackets)
}
```

### 指标服务器

```go
import "github.com/Haibara-Ai97/netprobe/pkg/metrics"

// 创建指标服务器
config := metrics.DefaultServerConfig()
config.Port = 8081

server := metrics.NewServer(config)

// 启动服务器
go func() {
    if err := server.Start(ctx, collector); err != nil {
        log.Fatal(err)
    }
}()

// 访问 http://localhost:8081/metrics 查看指标
```

## 📊 监控数据与指标

### 网络流量指标

| 指标名称 | 类型 | 描述 |
|---------|------|-----|
| `netprobe_interface_rx_packets_total` | Counter | 接口接收数据包总数 |
| `netprobe_interface_tx_packets_total` | Counter | 接口发送数据包总数 |
| `netprobe_interface_rx_bytes_total` | Counter | 接口接收字节总数 |
| `netprobe_interface_tx_bytes_total` | Counter | 接口发送字节总数 |
| `netprobe_interface_rx_packets_rate` | Gauge | 接口接收数据包速率 (packets/sec) |
| `netprobe_interface_tx_packets_rate` | Gauge | 接口发送数据包速率 (packets/sec) |
| `netprobe_interface_rx_bytes_rate` | Gauge | 接口接收字节速率 (bytes/sec) |
| `netprobe_interface_tx_bytes_rate` | Gauge | 接口发送字节速率 (bytes/sec) |

### 流量分析数据

```go
// 网络流量 Key
type FlowKey struct {
    SrcIP   uint32  // 源 IP 地址
    DstIP   uint32  // 目标 IP 地址
    SrcPort uint16  // 源端口
    DstPort uint16  // 目标端口
    Proto   uint8   // 协议类型 (TCP/UDP/ICMP)
}

// 接口统计数据
type InterfaceStats struct {
    InterfaceName      string    // 接口名称
    InterfaceIndex     uint32    // 接口索引
    IngressPackets     uint64    // 入站数据包数
    IngressBytes       uint64    // 入站字节数
    EgressPackets      uint64    // 出站数据包数
    EgressBytes        uint64    // 出站字节数
    IngressPacketsRate float64   // 入站包速率
    IngressBytesRate   float64   // 入站字节速率
    EgressPacketsRate  float64   // 出站包速率
    EgressBytesRate    float64   // 出站字节速率
    LastUpdated        time.Time // 最后更新时间
}
```

### eBPF 数据结构

```c
// 流量识别键 (C 结构体)
struct flow_key {
    __u32 src_ip;      // 源 IP 地址
    __u32 dst_ip;      // 目标 IP 地址  
    __u16 src_port;    // 源端口
    __u16 dst_port;    // 目标端口
    __u8  proto;       // 协议类型
};

// TC 设备统计键
struct tc_device_key {
    __u32 ifindex;     // 网络接口索引
    __u32 direction;   // 流量方向 (0=ingress, 1=egress)
    __u32 stat_type;   // 统计类型 (0=packets, 1=bytes)
};
```

## 🚧 后续开发规划

基于当前的 eBPF TC 监控基础，NetProbe 将沿着以下技术路线图发展，构建完整的云原生网络可观测性平台：

### 📈 第一阶段：网络监控能力增强 (v0.2-v0.3)

#### 1.1 多层网络监控
- **XDP 层增强**：完善网卡驱动层数据包拦截，提供更高性能的包处理能力
- **Socket 层监控**：添加 Socket 层连接跟踪，监控应用层网络连接状态和数据传输
- **Netfilter 集成**：在 Netfilter 各链 (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING) 进行监控，实现网络栈全链路观测

#### 1.2 协议深度解析
- **TCP/UDP 增强**：扩展当前的基础协议解析，添加连接状态跟踪、重传分析、拥塞控制监控
- **ICMP 监控**：添加 ICMP 协议解析，支持网络连通性和错误诊断
- **IPv6 支持**：扩展对 IPv6 协议的完整支持
- **VLAN/MPLS 标签**：支持复杂网络环境中的标签协议解析

### 🏗️ 第二阶段：容器网络智能化 (v0.4-v0.5)

#### 2.1 Kubernetes 深度集成
- **CNI 插件兼容**：支持 Calico、Flannel、Cilium 等主流 CNI 插件的网络监控
- **Pod 网络拓扑**：基于 eBPF 程序自动发现和构建 Pod 间网络拓扑图
- **Service Mesh 感知**：集成 Istio、Linkerd 等 Service Mesh 的网络层监控
- **Network Policy 监控**：实时监控 Kubernetes Network Policy 的执行效果

#### 2.2 容器网络性能优化
- **网络瓶颈识别**：基于流量模式分析识别网络瓶颈和热点
- **QoS 监控**：监控服务质量指标，如延迟、抖动、丢包率
- **带宽预测**：基于历史数据预测网络带宽需求

### 🔍 第三阶段：网络拓扑与可视化 (v0.6-v0.7)

#### 3.1 智能拓扑发现
- **自动拓扑构建**：基于网络流量自动发现和构建网络拓扑
- **依赖关系图**：构建服务间依赖关系图和通信路径
- **网络分段识别**：自动识别网络分段和安全域边界

#### 3.2 可视化与分析
- **实时拓扑图**：Web 界面展示实时网络拓扑和流量热力图
- **流量路径追踪**：可视化数据包在网络中的完整路径
- **异常可视化**：突出显示网络异常和安全威胁

### 🛡️ 第四阶段：应用层与安全增强 (v0.8-v1.0)

#### 4.1 应用层协议监控
- **HTTP/HTTPS 解析**：解析 HTTP 请求响应，监控 API 调用和响应时间
- **gRPC 监控**：支持 gRPC 协议的调用链追踪和性能监控
- **数据库协议**：支持 MySQL、PostgreSQL、Redis 等数据库协议监控
- **消息队列监控**：支持 Kafka、RabbitMQ 等消息中间件的网络层监控

#### 4.2 高级安全分析
- **机器学习异常检测**：使用 ML 算法检测异常网络行为模式
- **威胁情报集成**：集成外部威胁情报，识别已知恶意 IP 和域名
- **零日攻击检测**：基于行为分析检测未知网络攻击
- **自动响应机制**：结合 Kubernetes Network Policy 实现自动化安全响应

### 🤖 第五阶段：AI 驱动的网络优化 (v1.1+)

#### 5.1 LLM 网络智能优化
- **智能配置建议**：基于 LLM 分析网络性能数据，提供配置优化建议
- **自动故障诊断**：使用 AI 自动分析网络故障，提供修复建议
- **性能调优助手**：AI 驱动的网络性能调优和容量规划
- **自然语言查询**：支持自然语言查询网络状态和历史数据

#### 5.2 预测性网络运维
- **故障预测**：基于历史数据和模式识别预测网络故障
- **容量规划**：AI 驱动的网络容量规划和扩容建议
- **成本优化**：智能分析网络资源使用，提供成本优化方案

### 📊 技术架构演进

```
当前架构 (v0.1)           目标架构 (v1.0+)
┌─────────────────┐       ┌─────────────────────────────────────┐
│   eBPF TC       │  -->  │         AI 网络智能平台              │
│   基础监控      │       ├─────────────────────────────────────┤
└─────────────────┘       │ LLM    │ 机器学习 │ 预测分析 │ 自动化 │
                          ├─────────────────────────────────────┤
                          │ 应用层协议 │ 安全分析 │ 拓扑发现    │
                          ├─────────────────────────────────────┤
                          │ K8s 集成   │ Service Mesh │ CNI    │
                          ├─────────────────────────────────────┤
                          │ XDP │ TC │ Socket │ Netfilter      │
                          └─────────────────────────────────────┘
```

### 🎯 里程碑时间表

- **Q1 2025**: v0.2 - 多层监控完成
- **Q2 2025**: v0.4 - Kubernetes 深度集成
- **Q3 2025**: v0.6 - 网络拓扑可视化
- **Q4 2025**: v0.8 - 应用层协议支持
- **Q1 2026**: v1.0 - AI 驱动的网络优化

## 🛠️ 开发指南

### 扩展 eBPF 程序

1. **添加新的 Map**：
```go
// 在 ebpf/network/monitor.c 中添加新的 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct custom_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} custom_stats SEC(".maps");
```

2. **扩展统计收集**：
```go
// 在 pkg/collector/ 中添加新的收集器
type CustomCollector struct {
    manager *ebpf.Manager
}

func (c *CustomCollector) Collect() (CustomStats, error) {
    // 实现自定义统计收集逻辑
    return stats, nil
}
```

3. **添加新指标**：
```go
// 在 pkg/metrics/ 中注册新的 Prometheus 指标
var customMetric = prometheus.NewGaugeVec(
    prometheus.GaugeOpts{
        Name: "netprobe_custom_metric",
        Help: "Custom network metric",
    },
    []string{"interface", "direction"},
)
```

### 性能优化建议

| 组件 | 优化策略 | 性能影响 |
|------|---------|----------|
| **eBPF Maps** | 合理设置 MaxEntries，避免哈希冲突 | 高 |
| **收集间隔** | 根据网络流量调整收集频率 (1-10s) | 中 |
| **内存限制** | 移除 rlimit 限制，允许大内存使用 | 高 |
| **原子操作** | 使用 `__sync_fetch_and_add` 保证线程安全 | 中 |
| **数据处理** | 批量处理 Map 数据，减少系统调用 | 中 |

### 故障排查

```bash
# 检查 eBPF 程序是否正确加载
sudo bpftool prog list | grep netprobe

# 查看 eBPF Maps 状态
sudo bpftool map list

# 检查内核日志中的 eBPF 相关错误
sudo dmesg | grep -i bpf

# 验证网络接口是否正确附加
sudo bpftool net list

# 查看 TC 程序附加状态
sudo tc qdisc show dev eth0
```

## 🔐 安全与生产考虑

### 权限要求
- ⚠️ **Root 权限**：eBPF 程序加载需要 CAP_BPF 或 root 权限
- ⚠️ **内核兼容性**：确保 Linux 内核版本 ≥ 4.18
- ⚠️ **SELinux/AppArmor**：可能需要配置安全策略允许 eBPF 操作

### 资源监控
```bash
# 监控 eBPF 程序内存使用
cat /proc/sys/kernel/unprivileged_bpf_disabled

# 查看 eBPF 程序 CPU 使用情况
perf top -p $(pgrep netprobe-agent)

# 监控 Map 内存占用
sudo bpftool map show | grep netprobe
```

### 生产部署建议
- 📊 **资源限制**：在 Kubernetes 中设置合适的 CPU/内存限制
- 🔄 **滚动更新**：使用 DaemonSet 进行滚动更新，避免监控中断
- 📈 **监控告警**：配置 Prometheus 告警规则监控 Agent 健康状态
- 🔍 **日志收集**：配置日志收集和分析，便于问题排查

## 📚 学习资源与社区

### 官方文档
- [eBPF 官方网站](https://ebpf.io/) - eBPF 技术概述和学习资源
- [Cilium/eBPF 库文档](https://pkg.go.dev/github.com/cilium/ebpf) - Go eBPF 库 API 文档
- [BPF 内核文档](https://docs.kernel.org/bpf/) - Linux 内核 BPF 子系统文档
- [Kubernetes 网络文档](https://kubernetes.io/docs/concepts/cluster-administration/networking/) - K8s 网络基础

### 相关项目
- [Cilium](https://github.com/cilium/cilium) - 基于 eBPF 的网络和安全解决方案
- [Falco](https://github.com/falcosecurity/falco) - eBPF 运行时安全监控
- [Pixie](https://github.com/pixie-io/pixie) - Kubernetes 可观测性平台
- [Katran](https://github.com/facebookincubator/katran) - 基于 eBPF 的负载均衡器

### 贡献指南
1. **Fork 项目**并创建特性分支
2. **编写测试**确保新功能正确性
3. **更新文档**包括 API 文档和用户指南
4. **提交 PR**并填写详细的变更说明

---

**NetProbe** 致力于构建高性能、易用的云原生网络监控解决方案。通过 eBPF 技术，我们在内核空间实现零拷贝的网络数据处理，为云原生环境提供实时、准确的网络可观测性。
