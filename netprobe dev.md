# NetProbe 发展路线图

> 基于当前 eBPF/TC 网络监控基础，构建完整的云原生网络观测与智能优化平台

## 🏗️ 核心架构演进

### 当前架构状态 ✅
```
用户空间 (Go)           内核空间 (eBPF)
┌─────────────────┐    ┌─────────────────┐
│  NetProbe Agent │    │     monitor.c    │
│  ├─ Collector   │◄───┤  ├─ XDP Hook     │
│  ├─ Metrics     │◄───┤  ├─ TC Ingress   │
│  └─ Exporter    │◄───┤  └─ TC Egress    │
└─────────────────┘    └─────────────────┘
```

### 目标架构愿景 🎯
```
┌─────────────────────────────────────────────────────────────┐
│                    NetProbe 智能网络观测平台                   │
├─────────────────────────────────────────────────────────────┤
│  Data Layer   │  Processing Layer │  Analysis Layer │ Action │
│  ┌─────────┐  │  ┌─────────────┐  │  ┌────────────┐ │ Layer  │
│  │ eBPF    │──┼─►│ Stream      │──┼─►│ Topology   │ │ ┌────┐ │
│  │ Hooks   │  │  │ Processing  │  │  │ Discovery  │ │ │LLM │ │
│  └─────────┘  │  └─────────────┘  │  └────────────┘ │ │Opt │ │
│               │                   │                 │ └────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 📊 第一阶段：多层网络监控增强 (基于现有基础)

### 1.1 XDP 层优化 🚀
**当前状态**: 已实现基础 XDP hook 和包统计  
**发展目标**:
- **性能优化**: XDP_REDIRECT 支持，零拷贝优化
- **高级过滤**: 基于 BPF 程序的智能包过滤
- **负载均衡**: XDP 层的流量分发和负载均衡
- **DDoS 防护**: 实时流量分析和攻击检测

```c
// 扩展 monitor.c 支持高级 XDP 功能
SEC("xdp/advanced_filter")
int xdp_advanced_filter(struct xdp_md *ctx) {
    // 智能过滤逻辑
    // DDoS 检测算法
    // 负载均衡算法
}
```

### 1.2 Socket 层监控 🔌
**依赖**: 扩展当前 eBPF 程序  
**实现路径**:
```
pkg/ebpf/socket_loader.go  ←── 新增
├─ SocketInfo 结构体定义
├─ Socket 事件收集
└─ Connection 状态跟踪

ebpf/socket/monitor.c      ←── 新增
├─ connect/accept hook
├─ send/recv 统计
└─ 连接异常检测
```

### 1.3 Netfilter 集成 🛡️
**架构扩展**:
```
pkg/netfilter/           ←── 新增目录
├─ hook_manager.go      ←── Netfilter hook 管理
├─ rule_engine.go       ←── 规则引擎
└─ packet_analyzer.go   ←── 包分析器

ebpf/netfilter/         ←── 新增目录
├─ prerouting.c        ←── PREROUTING hook
├─ postrouting.c       ←── POSTROUTING hook
└─ forward.c           ←── FORWARD hook
```

## 🐳 第二阶段：容器网络感知与K8s深度集成

### 2.1 容器网络发现 📡
**基于现有**: 扩展 `pkg/collector/` 模块
```go
// pkg/collector/container_collector.go
type ContainerNetworkCollector struct {
    k8sClient    kubernetes.Interface
    ebpfLoader   *ebpf.NetworkLoader  // 复用现有
    cgroupMap    *ebpf.Map           // 新增 cgroup 映射
}

// 容器网络事件结构
type ContainerNetworkEvent struct {
    PodName       string
    Namespace     string
    ContainerID   string
    NetworkNS     uint32
    InterfaceInfo InterfaceDetails
    FlowStats     FlowKey              // 复用现有结构
}
```

### 2.2 Kubernetes 原生集成 ⚓
**扩展现有**: 基于 `deploy/agent.yaml`
```yaml
# 增强版 K8s 部署配置
apiVersion: v1
kind: ConfigMap
metadata:
  name: netprobe-config
data:
  config.yaml: |
    ebpf:
      programs: ["xdp", "tc", "socket", "netfilter"]
    kubernetes:
      enable_pod_monitoring: true
      enable_service_discovery: true
      enable_network_policy_monitoring: true
```

### 2.3 CNI 插件适配 🔗
**新增模块**:
```
pkg/cni/                 ←── 新增
├─ detector.go          ←── CNI 类型检测
├─ calico_adapter.go    ←── Calico 适配器
├─ flannel_adapter.go   ←── Flannel 适配器
└─ cilium_adapter.go    ←── Cilium 适配器
```

## 🔍 第三阶段：协议深度解析与应用层监控

### 3.1 协议解析引擎 📋
**扩展架构**:
```
pkg/protocol/            ←── 新增
├─ parser_manager.go    ←── 解析器管理
├─ tcp_analyzer.go      ←── TCP 深度分析
├─ udp_analyzer.go      ←── UDP 分析
├─ http_parser.go       ←── HTTP 协议解析
├─ grpc_parser.go       ←── gRPC 协议支持
└─ custom_parser.go     ←── 自定义协议支持

ebpf/protocol/          ←── 对应 eBPF 程序
├─ http_monitor.c      ←── HTTP 请求监控
├─ grpc_monitor.c      ←── gRPC 调用追踪
└─ ssl_monitor.c       ←── SSL/TLS 分析
```

### 3.2 应用性能监控 (APM) 📊
**基于现有指标系统**: 扩展 `pkg/metrics/`
```go
// pkg/metrics/apm_metrics.go
type APMMetrics struct {
    HTTPRequestLatency     *prometheus.HistogramVec
    HTTPRequestRate        *prometheus.CounterVec
    HTTPErrorRate          *prometheus.CounterVec
    DatabaseConnections    *prometheus.GaugeVec
    ServiceDependencyMap   *prometheus.GaugeVec
}
```

## 🗺️ 第四阶段：网络拓扑发现与可视化

### 4.1 智能拓扑发现 🕸️
**数据融合**:
```
pkg/topology/            ←── 新增
├─ discoverer.go        ←── 拓扑发现引擎
├─ graph_builder.go     ←── 网络图构建
├─ relationship.go      ←── 关系推断
└─ export.go           ←── 拓扑数据导出

// 基于现有 FlowKey 扩展
type NetworkRelationship struct {
    Source      ServiceEndpoint
    Destination ServiceEndpoint
    Protocol    string
    FlowStats   FlowKey         // 复用现有
    Latency     time.Duration
    Reliability float64
}
```

### 4.2 可视化组件 🎨
**Web UI 集成**:
```
web/                     ←── 新增前端
├─ dashboard/           ←── 监控面板
├─ topology/           ←── 拓扑图展示
├─ alerts/             ←── 告警管理
└─ api/               ←── REST API

pkg/api/               ←── 后端 API
├─ handlers.go        ←── HTTP 处理器
├─ websocket.go      ←── 实时数据推送
└─ graphql.go        ←── GraphQL 接口
```

## 🔄 第五阶段：网络健康分析与异常检测

### 5.1 实时异常检测 ⚠️
**基于现有统计**: 扩展 `pkg/collector/tc_collector.go`
```go
// pkg/analysis/anomaly_detector.go
type AnomalyDetector struct {
    BaselineStats   map[string]*NetworkBaseline
    AlertThresholds map[string]float64
    MLModel        *AnomalyModel
}

type NetworkAnomaly struct {
    Type        AnomalyType
    Severity    Severity
    FlowInfo    FlowKey    // 复用现有结构
    Timestamp   time.Time
    Description string
    Suggestions []string
}
```

### 5.2 性能基线建立 📈
**时序数据分析**:
```
pkg/baseline/           ←── 新增
├─ collector.go        ←── 基线数据收集
├─ analyzer.go         ←── 趋势分析
├─ predictor.go        ←── 性能预测
└─ alerter.go         ←── 智能告警
```

## 🤖 第六阶段：LLM 集成与智能优化

### 6.1 网络智能助手 🧠
**AI 驱动的网络分析**:
```
pkg/ai/                 ←── 新增 AI 模块
├─ llm_client.go       ←── LLM 客户端
├─ prompt_engineer.go  ←── 提示工程
├─ network_advisor.go  ←── 网络顾问
└─ auto_optimizer.go   ←── 自动优化

// 基于监控数据的智能分析
type NetworkAnalysisRequest struct {
    TimeRange    TimeRange
    FlowStats    []FlowKey        // 基于现有数据
    Anomalies    []NetworkAnomaly
    TopologyInfo NetworkTopology
}
```

### 6.2 自动优化建议 ⚡
**智能配置推荐**:
```go
type OptimizationSuggestion struct {
    Type          OptimizationType
    Priority      Priority
    Impact        ImpactAssessment
    Implementation string
    RollbackPlan  string
    Validation    ValidationSteps
}

// 支持的优化类型
const (
    NetworkPolicy     OptimizationType = "network_policy"
    ResourceAllocation OptimizationType = "resource_allocation"
    TrafficShaping    OptimizationType = "traffic_shaping"
    ServiceMesh       OptimizationType = "service_mesh"
)
```

## 🎯 实施优先级与时间线

### Phase 1 (1-2 个月): 基础增强
1. **Socket 层监控** - 扩展现有 eBPF 程序
2. **Netfilter 集成** - 新增防火墙层监控
3. **性能优化** - XDP 程序优化

### Phase 2 (2-3 个月): K8s 深度集成
1. **容器网络发现** - 基于现有 collector 架构
2. **CNI 适配** - 支持主流 CNI 插件
3. **Pod 级监控** - 细粒度容器网络监控

### Phase 3 (3-4 个月): 协议解析
1. **HTTP/gRPC 解析** - 应用层协议支持
2. **APM 功能** - 应用性能监控
3. **SSL/TLS 分析** - 加密流量分析

### Phase 4 (2-3 个月): 拓扑与可视化
1. **拓扑发现引擎** - 网络关系推断
2. **Web UI 开发** - 可视化界面
3. **实时监控面板** - 运维友好界面

### Phase 5 (2-3 个月): 智能分析
1. **异常检测算法** - 基于统计和 ML
2. **性能基线建立** - 历史数据分析
3. **智能告警** - 减少误报

### Phase 6 (3-4 个月): AI 增强
1. **LLM 集成** - 智能网络分析
2. **自动优化** - AI 驱动的配置建议
3. **持续学习** - 基于反馈的模型优化

## 🔄 关键集成点

### 与现有架构的无缝集成
- **复用 eBPF 基础**: 基于现有 `monitor.c` 和 `network_loader.go`
- **扩展 Metrics 系统**: 基于现有 Prometheus 集成
- **增强 Collector**: 扩展现有收集器架构
- **保持向后兼容**: 现有 API 和配置格式保持稳定

### 数据一致性保证
- **统一数据模型**: 基于现有 `FlowKey` 和统计结构
- **事件驱动架构**: 基于现有事件处理机制  
- **可观测性增强**: 基于现有监控和告警框架