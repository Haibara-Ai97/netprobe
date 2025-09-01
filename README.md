# NetProbe - 高性能 eBPF 网络监控系统

## 🎯 项目概述

NetProbe 是一个基于 **Cilium/eBPF** 库实现的云原生网络监控系统，专为 Kubernetes 环境设计。它利用 eBPF 技术在内核空间进行高效的网络数据包处理，提供实时、低开销的网络流量监控和安全分析。

## ✨ 核心特性

### 🚀 高性能监控
- **零拷贝处理**：基于 eBPF 的内核级数据包处理
- **多层监控**：完整支持 XDP、TC (Traffic Control)、Socket 和 Netfilter 层监控
- **VXLAN 隧道监控**：专门针对容器网络 VXLAN 封装的深度监控
- **实时统计**：毫秒级网络流量统计和异常检测

### 🔒 安全分析
- **端口扫描检测**：识别异常端口扫描行为
- **异常连接监控**：检测可疑网络连接模式
- **DDoS 防护**：实时流量分析和攻击检测

### 🎛️ 云原生设计
- **Kubernetes 集成**：原生支持容器网络监控和 Pod/Service 元数据关联
- **Flannel VXLAN 支持**：深度集成 Flannel 网络，监控 VXLAN 隧道流量
- **Prometheus 兼容**：标准 metrics 格式导出
- **容器感知**：Pod 和 Service 级别的网络可视化和拓扑发现

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
│  │         pkg/ebpf/manager.go               │ │         │        │
│  │    (统一 eBPF 程序生命周期管理)           │ │         │        │
│  └─────────────────────┬─────────────────────┘ │         │        │
│           │            │  pkg/kubernetes/      │         │        │
│           │            │  ┌─────────────────┐  │         │        │
│           │            │  │ K8s 元数据集成  │  │         │        │
│           │            │  │ VXLAN 拓扑发现  │  │         │        │
│           │            │  │ 流量关联分析    │  │         │        │
│           ▼            │  └─────────────────┘  │         │        │
├─────────────────────────┼─────────────────────────────────┼────────┤
│                        ▼                               │        │
│                   内核空间 (Kernel Space)                │        │
├─────────────────────────────────────────────────────────┼────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────┼────┐   │
│  │ ebpf/network/   │ │ ebpf/socket/    │ │ ebpf/vxlan/ │    │   │
│  │ monitor.c       │ │ monitor.c       │ │ monitor.c   │    │   │
│  │                 │ │                 │ │             │    │   │
│  │ XDP Hook        │ │ Socket/kprobe   │ │ VXLAN 解析  │    │   │
│  │ TC Ingress      │ │ 连接跟踪        │ │ VNI 识别    │    │   │
│  │ TC Egress       │ │ 系统调用监控    │ │ 隧道统计    │    │   │
│  └─────────────────┘ └─────────────────┘ └─────────────┼────┘   │
│           │                   │                   │    │        │
│  ┌─────────────────┐ ┌─────────────────┐         │    │        │
│  │ ebpf/netfilter/ │ │      eBPF Maps              │    │        │
│  │ monitor.c       │ │                             │    │        │
│  │                 │ │ packet_stats │flow_stats   │    │        │
│  │ Netfilter Hook  │ │ socket_events│vxlan_stats  │    │        │
│  │ 防火墙层监控    │ │ device_stats │connection_map│    │        │
│  └─────────────────┘ └─────────────────────────────┼────┼────────┤
│           ▼                   ▼                   ▼    ▼        │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                Ring Buffer 事件传输                       │ │
│  │  network_events │ socket_events │ vxlan_events             │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 数据流向
1. **多层数据包捕获**：
   - **XDP 层**：在网卡驱动层进行最早期数据包拦截
   - **TC 层**：在流量控制层进行入站/出站监控
   - **Socket 层**：监控应用层连接建立、数据传输和关闭
   - **Netfilter 层**：在防火墙层进行安全策略监控
   - **VXLAN 解析**：专门解析容器网络 VXLAN 隧道封装

2. **统计更新**：使用原子操作更新 eBPF Maps 中的统计数据
3. **事件传输**：通过 Ring Buffer 高效传输网络事件到用户空间
4. **数据收集**：Go 收集器定期读取 eBPF Maps 数据和处理事件
5. **Kubernetes 关联**：将网络流量与 Pod、Service、Node 元数据关联
6. **指标计算**：计算实时速率、VXLAN 拓扑和聚合统计信息
7. **指标导出**：通过 Prometheus 格式 HTTP 接口暴露指标

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
  --interface-filter=eth0,wlan0 \
  --enable-xdp=true \
  --enable-socket=true \
  --enable-vxlan=true \
  --kubeconfig=/path/to/kubeconfig

# 查看监控指标
curl http://localhost:8081/metrics

# 查看 Kubernetes 集成状态
curl http://localhost:8081/api/cluster

# 查看 VXLAN 拓扑信息
curl http://localhost:8081/api/flannel

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

// 附加不同层的监控程序
// 1. 网络层监控 (XDP + TC)
err = manager.AttachNetworkMonitor("eth0")
if err != nil {
    return err
}

// 2. Socket 层监控
socketLoader := ebpf.NewSocketLoader()
err = socketLoader.LoadPrograms()
if err != nil {
    return err
}
err = socketLoader.AttachSocketPrograms()
if err != nil {
    return err
}

// 3. VXLAN 监控
vxlanLoader := ebpf.NewVXLANLoader()
err = vxlanLoader.LoadPrograms()
if err != nil {
    return err
}
err = vxlanLoader.AttachVXLANPrograms("flannel.1")
if err != nil {
    return err
}

// 获取综合网络统计
stats, err := manager.GetNetworkStats()
if err != nil {
    return err
}
```

### Kubernetes 网络集成

```go
import "github.com/Haibara-Ai97/netprobe/pkg/kubernetes"

// 创建 Kubernetes 网络集成器
integrator, err := kubernetes.NewK8sNetworkIntegrator("/path/to/kubeconfig")
if err != nil {
    return err
}
defer integrator.Stop()

// 启动集成器
err = integrator.Start()
if err != nil {
    return err
}

// 处理 VXLAN 流量事件
integrator.ProcessVXLANEvent("10.244.0.1", "10.244.1.1", 8080, 80, 6, 1, 1500)

// 获取 Pod 网络拓扑
topology := integrator.GetTopology()
for ip, pod := range topology.IPToPod {
    fmt.Printf("Pod %s/%s -> IP %s\n", pod.Namespace, pod.Name, ip)
}

// 获取 Flannel VXLAN 拓扑
flannelTopology := integrator.GetFlannelTopology()
for _, node := range flannelTopology.Nodes {
    fmt.Printf("Node %s: CIDR %s, VNI %d, VTEP MAC %s\n", 
        node.NodeName, node.PodCIDR, node.VNI, node.VTepMAC)
}

// 获取流量统计
stats := integrator.GetTrafficStats()
fmt.Printf("Total flows: %d, VXLAN flows: %d, Inter-node flows: %d\n",
    stats.TotalFlows, stats.VXLANFlows, stats.InterNodeFlows)
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

### Socket 连接指标

| 指标名称 | 类型 | 描述 |
|---------|------|-----|
| `netprobe_socket_connections_total` | Counter | Socket 连接总数 |
| `netprobe_socket_bytes_sent_total` | Counter | Socket 发送字节总数 |
| `netprobe_socket_bytes_recv_total` | Counter | Socket 接收字节总数 |
| `netprobe_socket_events_total` | Counter | Socket 事件总数 (connect/accept/close) |

### VXLAN 隧道指标

| 指标名称 | 类型 | 描述 |
|---------|------|-----|
| `netprobe_vxlan_packets_total` | Counter | VXLAN 数据包总数 |
| `netprobe_vxlan_bytes_total` | Counter | VXLAN 字节总数 |
| `netprobe_vxlan_tunnels_active` | Gauge | 活跃 VXLAN 隧道数 |
| `netprobe_vxlan_vni_stats` | Counter | 按 VNI 分组的流量统计 |

### Kubernetes 集成指标

| 指标名称 | 类型 | 描述 |
|---------|------|-----|
| `netprobe_k8s_pod_flows_total` | Counter | Pod 间流量总数 |
| `netprobe_k8s_service_flows_total` | Counter | Service 访问流量总数 |
| `netprobe_k8s_inter_node_flows_total` | Counter | 跨节点流量总数 |
| `netprobe_k8s_intra_node_flows_total` | Counter | 节点内流量总数 |

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

// Socket 事件结构
type SocketEvent struct {
    Timestamp  uint64    // 事件时间戳（纳秒）
    EventType  uint32    // 事件类型: 0=connect, 1=accept, 2=close, 3=send, 4=recv
    PID        uint32    // 进程ID
    TID        uint32    // 线程ID
    SrcIP      uint32    // 源IP
    DstIP      uint32    // 目标IP
    SrcPort    uint16    // 源端口
    DstPort    uint16    // 目标端口
    Protocol   uint8     // 协议
    BytesSent  uint32    // 发送字节数
    BytesRecv  uint32    // 接收字节数
    Comm       [16]byte  // 进程名
}

// VXLAN 事件结构
type VXLANEvent struct {
    SrcIP      uint32    // 外层源IP (VTEP)
    DstIP      uint32    // 外层目标IP (VTEP)
    VNI        uint32    // VXLAN Network Identifier
    InnerSrcIP uint32    // 内层源IP (Pod IP)
    InnerDstIP uint32    // 内层目标IP (Pod IP)
    PacketLen  uint16    // 数据包长度
    Timestamp  uint64    // 时间戳
}

// Kubernetes 流量关联
type TrafficFlow struct {
    SrcPod    *PodInfo    // 源 Pod 信息
    DstPod    *PodInfo    // 目标 Pod 信息
    SrcNode   *NodeInfo   // 源节点信息
    DstNode   *NodeInfo   // 目标节点信息
    Service   *ServiceInfo // 服务信息
    SrcIP     string      // 源IP
    DstIP     string      // 目标IP
    SrcPort   uint16      // 源端口
    DstPort   uint16      // 目标端口
    Protocol  uint8       // 协议
    VNI       uint32      // VXLAN VNI (如果适用)
    Direction string      // 流量方向: intra-node, inter-node, ingress, egress
    Timestamp time.Time   // 时间戳
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

// Socket 事件结构体
struct socket_event {
    __u64 timestamp;        // 事件时间戳
    __u32 event_type;       // 事件类型
    __u32 pid;              // 进程ID
    __u32 tid;              // 线程ID
    __u32 src_ip;           // 源IP
    __u32 dst_ip;           // 目标IP
    __u16 src_port;         // 源端口
    __u16 dst_port;         // 目标端口
    __u8  protocol;         // 协议
    __u32 bytes_sent;       // 发送字节数
    __u32 bytes_recv;       // 接收字节数
    char  comm[16];         // 进程名
};

// VXLAN 统计键
struct vxlan_key {
    __u32 vni;             // VXLAN Network Identifier
    __u32 outer_src_ip;    // 外层源IP (VTEP)
    __u32 outer_dst_ip;    // 外层目标IP (VTEP)
};

// VXLAN 统计值
struct vxlan_stats {
    __u64 packets;         // 数据包数
    __u64 bytes;           // 字节数
    __u64 last_seen;       // 最后见到时间
};

// TC 设备统计键
struct tc_device_key {
    __u32 ifindex;     // 网络接口索引
    __u32 direction;   // 流量方向 (0=ingress, 1=egress)
    __u32 stat_type;   // 统计类型 (0=packets, 1=bytes)
};

// Netfilter 钩子统计
struct netfilter_stats {
    __u64 packets_processed;  // 处理的数据包数
    __u64 packets_dropped;    // 丢弃的数据包数
    __u64 bytes_processed;    // 处理的字节数
    __u32 hook_point;         // 钩子点位置
};
```

## 🚧 后续开发规划

基于当前已实现的多层 eBPF 监控基础（XDP、TC、Socket、Netfilter、VXLAN）和 Kubernetes 网络集成，NetProbe 将沿着以下技术路线图发展：

### 📈 第一阶段：监控能力深化 (v0.2-v0.3)

#### 1.1 协议解析增强 ✅ 部分完成
- **TCP/UDP 状态跟踪** ✅：已实现 Socket 层连接跟踪和状态监控
- **VXLAN 隧道监控** ✅：已完成 VXLAN 封装解析和 VNI 识别
- **ICMP 监控**：添加 ICMP 协议解析，支持网络连通性和错误诊断
- **IPv6 支持**：扩展对 IPv6 协议的完整支持
- **VLAN/MPLS 标签**：支持复杂网络环境中的标签协议解析

#### 1.2 性能监控指标扩展
- **网络延迟测量**：基于 eBPF 时间戳计算端到端延迟
- **丢包率统计**：在各个网络层监控数据包丢失情况
- **带宽利用率**：实时计算网络带宽使用率和突发流量
- **连接质量评估**：TCP 重传率、RTT 变化等质量指标

### 🏗️ 第二阶段：容器网络智能化 (v0.4-v0.5)

#### 2.1 Kubernetes 深度集成 ✅ 已实现基础功能
- **Pod/Service 元数据关联** ✅：已实现网络流量与 Kubernetes 资源的自动关联
- **Flannel VXLAN 集成** ✅：已支持 Flannel 网络拓扑发现和 VXLAN 隧道监控
- **CNI 插件兼容**：扩展支持 Calico、Cilium 等其他主流 CNI 插件
- **Service Mesh 感知**：集成 Istio、Linkerd 等 Service Mesh 的网络层监控
- **Network Policy 监控**：实时监控 Kubernetes Network Policy 的执行效果

#### 2.2 容器网络拓扑增强
- **实时拓扑构建** ✅：已实现基于网络流量的 Pod 间通信拓扑
- **跨节点流量分析** ✅：已支持节点间 VXLAN 隧道流量的详细分析
- **服务依赖图**：构建服务间依赖关系图和关键路径识别
- **网络分段可视化**：自动识别网络分段和安全域边界

### 🔍 第三阶段：网络拓扑与可视化 (v0.6-v0.7)

#### 3.1 智能拓扑发现 ✅ 基础实现完成
- **自动拓扑构建** ✅：已基于网络流量自动发现和构建网络拓扑
- **Flannel 网络映射** ✅：已实现 Flannel VXLAN 网络的完整拓扑映射
- **流量方向识别** ✅：已支持 intra-node、inter-node、ingress、egress 流量分类
- **VXLAN 隧道可视化** ✅：已实现 VNI、VTEP 和隧道端点的可视化
- **网络分段识别**：自动识别网络分段和安全域边界

#### 3.2 REST API 和查询能力 ✅ 已实现
- **HTTP API 服务** ✅：已提供完整的 REST API 接口
- **流量查询接口** ✅：支持按方向、命名空间、节点查询流量
- **元数据查询** ✅：支持 Pod、Service、Node 的 IP 反向查询
- **实时拓扑接口** ✅：提供实时网络拓扑和 Flannel 信息的 API
- **Top Talkers 分析** ✅：已实现流量最多的通信对分析

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
当前架构 (v0.1)                      目标架构 (v1.0+)
┌─────────────────────────────────┐   ┌─────────────────────────────────────┐
│   多层 eBPF 监控 ✅              │   │         AI 网络智能平台              │
│   ├─ XDP Hook ✅                │   ├─────────────────────────────────────┤
│   ├─ TC Ingress/Egress ✅       │   │ LLM    │ 机器学习 │ 预测分析 │ 自动化 │
│   ├─ Socket Layer ✅            │   ├─────────────────────────────────────┤
│   ├─ Netfilter Hook ✅          │   │ 应用层协议 │ 安全分析 │ 拓扑发现    │
│   └─ VXLAN Monitor ✅           │   ├─────────────────────────────────────┤
│                                 │   │ K8s 集成 ✅ │ Service Mesh │ CNI    │
│   Kubernetes 集成 ✅            │   ├─────────────────────────────────────┤
│   ├─ Pod/Service 关联 ✅        │   │ XDP ✅│ TC ✅│ Socket ✅│ Netfilter ✅│
│   ├─ Flannel VXLAN ✅           │   │ VXLAN ✅│ Ring Buffer ✅│ Maps ✅   │
│   ├─ 流量拓扑分析 ✅            │   └─────────────────────────────────────┘
│   └─ REST API ✅                │   
└─────────────────────────────────┘   
```

### 🎯 里程碑时间表

- **✅ Q4 2024**: v0.1 - 多层 eBPF 监控基础 + Kubernetes 集成完成
- **🚧 Q1 2025**: v0.2 - 协议解析增强 + 性能监控指标扩展  
- **📋 Q2 2025**: v0.4 - 其他 CNI 插件支持 + Service Mesh 集成
- **📋 Q3 2025**: v0.6 - Web 可视化界面 + 高级拓扑分析
- **📋 Q4 2025**: v0.8 - 应用层协议支持 + 智能安全分析
- **📋 Q1 2026**: v1.0 - AI 驱动的网络优化平台

## 🛠️ 开发指南

### 扩展 eBPF 程序

1. **添加新的 Socket 监控**：
```c
// 在 ebpf/socket/monitor.c 中添加新的 kprobe
SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx) {
    // 监控 TCP 发送事件
    struct socket_event event = {0};
    event.event_type = SOCKET_EVENT_SEND;
    event.timestamp = bpf_ktime_get_ns();
    
    // 发送到 Ring Buffer
    bpf_ringbuf_submit(&event, 0);
    return 0;
}
```

2. **添加 VXLAN 统计**：
```c
// 在 ebpf/vxlan/monitor.c 中添加 VNI 统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct vxlan_key));
    __uint(value_size, sizeof(struct vxlan_stats));
    __uint(max_entries, 4096);
} vxlan_flow_stats SEC(".maps");
```

3. **扩展统计收集**：
```go
// 在 pkg/ebpf/ 中使用新的 Loader
socketLoader := ebpf.NewSocketLoader()
vxlanLoader := ebpf.NewVXLANLoader()

// 处理 Socket 事件
socketLoader.AddEventHandler(&MySocketHandler{})

// 处理 VXLAN 事件  
vxlanLoader.AddEventHandler(&MyVXLANHandler{})
```

4. **Kubernetes 集成扩展**：
```go
// 创建网络集成器
integrator, err := kubernetes.NewK8sNetworkIntegrator(kubeconfig)
integrator.Start()

// 处理网络事件并关联 K8s 元数据
integrator.ProcessVXLANEvent(srcIP, dstIP, srcPort, dstPort, proto, vni, packetLen)

// 查询流量统计
stats := integrator.GetTrafficStats()
topology := integrator.GetFlannelTopology()
```

### 性能优化建议

| 组件 | 优化策略 | 性能影响 |
|------|---------|----------|
| **eBPF Maps** | 合理设置 MaxEntries，避免哈希冲突 | 高 |
| **Ring Buffer** | 调整 Ring Buffer 大小，批量处理事件 | 高 |
| **收集间隔** | 根据网络流量调整收集频率 (1-10s) | 中 |
| **内存限制** | 移除 rlimit 限制，允许大内存使用 | 高 |
| **原子操作** | 使用 `__sync_fetch_and_add` 保证线程安全 | 中 |
| **事件过滤** | 在 eBPF 层过滤不需要的事件，减少用户空间处理 | 高 |
| **K8s API 缓存** | 缓存 Pod/Service 元数据，减少 API 调用 | 中 |
| **VXLAN 解析** | 优化 VXLAN 头部解析，提高隧道监控效率 | 中 |

### 故障排查

```bash
# 检查所有 eBPF 程序是否正确加载
sudo bpftool prog list | grep -E "(netprobe|xdp|tc|socket|vxlan)"

# 查看具体的 eBPF Maps 状态
sudo bpftool map list | grep -E "(packet_stats|socket_events|vxlan_stats)"

# 检查 Ring Buffer 状态
sudo bpftool map dump name socket_events
sudo bpftool map dump name vxlan_events

# 检查内核日志中的 eBPF 相关错误
sudo dmesg | grep -i -E "(bpf|xdp|tc|socket|vxlan)"

# 验证网络接口是否正确附加
sudo bpftool net list

# 查看 TC 程序附加状态
sudo tc qdisc show dev eth0
sudo tc filter show dev eth0 ingress
sudo tc filter show dev eth0 egress

# 检查 XDP 程序状态
sudo bpftool net show dev eth0

# 查看 Socket kprobe 附加情况
sudo bpftool perf list

# 检查 VXLAN 接口状态
ip link show type vxlan
sudo bpftool net list | grep vxlan

# 测试 Kubernetes 集成
curl http://localhost:8081/api/cluster
curl http://localhost:8081/api/topology
curl http://localhost:8081/api/flannel

# 查看流量统计
curl http://localhost:8081/api/stats
curl "http://localhost:8081/api/flows?direction=inter-node"
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

## 🌟 v0.1 新特性总结

### 🔥 多层 eBPF 监控架构
NetProbe v0.1 实现了业界领先的多层 eBPF 网络监控架构：

#### 🚀 **XDP 层监控** - 网卡驱动层
- 在网络数据包进入内核协议栈之前进行拦截
- 提供最高性能的数据包处理能力
- 支持早期丢包检测和流量统计

#### 🔄 **TC 层监控** - 流量控制层  
- 支持 Ingress 和 Egress 方向的双向监控
- 提供详细的接口级流量统计
- 实现基于规则的流量分类和统计

#### 🔌 **Socket 层监控** - 应用连接层
- 基于 kprobe 和 tracepoint 监控 Socket 生命周期
- 跟踪 TCP/UDP 连接的建立、数据传输和关闭
- 提供进程级网络活动监控

#### 🛡️ **Netfilter 层监控** - 防火墙层
- 在 Netfilter 钩子点监控网络安全策略执行
- 支持防火墙规则效果分析
- 实现网络安全事件检测

#### 🌐 **VXLAN 隧道监控** - 容器网络层
- 专门针对容器网络 VXLAN 封装的深度解析
- 支持 VNI (VXLAN Network Identifier) 识别和统计
- 实现 VTEP (VXLAN Tunnel Endpoint) 拓扑发现

### 🎯 **Kubernetes 深度集成**
#### 📊 网络流量与元数据关联
- **Pod IP 反向查询**：根据 IP 地址快速定位对应的 Pod 信息
- **Service 流量识别**：自动识别访问 Kubernetes Service 的流量
- **Node 间通信分析**：详细分析跨节点的 Pod 通信模式

#### 🗺️ Flannel VXLAN 拓扑发现
- **VXLAN 网络映射**：自动发现 Flannel 网络的 VXLAN 配置
- **VNI 到节点映射**：建立 VXLAN Network Identifier 与 Kubernetes 节点的对应关系
- **VTEP MAC 地址管理**：跟踪 VXLAN Tunnel Endpoint 的 MAC 地址分配

#### 🔍 实时流量分析
- **流量方向分类**：intra-node (节点内)、inter-node (跨节点)、ingress/egress
- **Top Talkers 识别**：找出网络中通信最频繁的 Pod 和 Service
- **网络依赖分析**：构建服务间的网络依赖关系图

### 🛠️ **完整的 REST API 体系**
```bash
# 集群信息查询
GET /api/cluster

# 网络拓扑查询  
GET /api/topology

# Flannel 网络信息
GET /api/flannel

# 流量统计
GET /api/stats

# 流量查询 (支持多种过滤条件)
GET /api/flows?direction=inter-node
GET /api/flows?namespace=default  
GET /api/flows?node=worker-1

# 资源反向查询
GET /api/query/pod?ip=10.244.1.10
GET /api/query/service?ip=10.96.0.1
GET /api/query/node?ip=192.168.1.100

# 网络报告生成
GET /api/report
```

### 📈 **高性能事件处理**
- **Ring Buffer 架构**：使用 eBPF Ring Buffer 实现用户空间和内核空间的高效数据传输
- **事件驱动处理**：支持实时网络事件处理，毫秒级响应时间
- **批量数据处理**：优化的批量数据收集机制，降低系统开销
- **内存零拷贝**：基于 eBPF 的零拷贝数据处理，最大化性能

### 🎯 **生产级特性**
- **容器化部署**：提供完整的 Kubernetes DaemonSet 部署方案
- **健康检查**：内置健康检查端点，支持 Kubernetes 探针
- **Prometheus 集成**：标准 Prometheus metrics 格式，无缝集成监控系统
- **日志结构化**：使用 klog 提供结构化日志输出
- **优雅关闭**：支持信号处理和资源清理

**NetProbe v0.1** 为云原生环境提供了前所未有的网络可观测性能力，通过多层 eBPF 监控和 Kubernetes 深度集成，让网络监控变得简单而强大。

---

**NetProbe** 致力于构建高性能、易用的云原生网络监控解决方案。通过 eBPF 技术，我们在内核空间实现零拷贝的网络数据处理，为云原生环境提供实时、准确的网络可观测性。
