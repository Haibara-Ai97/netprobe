# KubeNetProbe - 基于 Cilium/eBPF 的网络监控

## 🎯 项目概述

KubeNetProbe 现在专注于使用 **Cilium/eBPF** 库实现高性能的 Kubernetes 网络监控。项目已经过清理，移除了所有不必要的代码，保留了最核心和实用的功能。

## ✨ 主要特性

- 🚀 **纯 Go 实现**：使用 cilium/ebpf 库，无需 CGO
- 🔒 **类型安全**：编译时错误检查，避免运行时问题
- 📊 **实时监控**：网络流量、连接状态、安全事件
- 🛡️ **安全分析**：端口扫描检测、异常连接监控
- 🎛️ **事件驱动**：基于 Ring Buffer 的高效事件处理
- 🔧 **云原生**：完全适配 Kubernetes 环境

## 📁 项目结构

```
kube-net-probe/
├── pkg/ebpf/                    # 核心 eBPF 实现
│   ├── go_implementation.go     # Cilium/eBPF 主要实现
│   ├── manager.go              # eBPF 程序管理器
│   └── program.go              # 程序生命周期管理
├── examples/                    # 示例程序
│   └── monitor.go              # 简化的监控示例
├── docs/                       # 文档
│   ├── cilium_ebpf_implementation.md
│   └── go_ebpf_implementation_guide.md
└── cmd/                        # 命令行工具
    ├── manager/                # 控制平面
    ├── agent/                  # 数据平面
    └── cli/                    # 命令行接口
```

## 🚀 快速开始

### 1. 环境要求

- Go 1.21+
- Linux 内核 4.18+
- Root 权限（用于加载 eBPF 程序）

### 2. 安装依赖

```bash
go mod tidy
```

### 3. 运行示例

```bash
# 编译示例程序
cd examples
go build -o monitor monitor.go

# 运行监控程序（需要 root 权限）
sudo ./monitor

# 或者指定网络接口
sudo NETWORK_INTERFACE=eth0 ./monitor
```

## 🔧 核心 API

### 创建监控器

```go
// 基础创建
monitor, err := ebpf.NewNetworkMonitor()

// 从对象文件创建（推荐生产环境）
monitor, err := ebpf.NewNetworkMonitorFromObjectFile("./network-monitor.o")
```

### 附加和监控

```go
// 附加到网络接口
err := monitor.AttachToInterface("eth0")

// 启动事件处理
err := monitor.StartEventProcessing()

// 获取统计信息
packetStats, err := monitor.GetPacketStats()
flowStats, err := monitor.GetFlowStats()
```

### 资源清理

```go
defer monitor.Close()
```

## 📊 监控数据

### 数据包统计
- RX/TX 包数量和字节数
- 协议分布统计
- 接口级别的流量统计

### 流量分析
- 活跃连接跟踪
- 流量模式识别
- 带宽使用分析

### 安全事件
- 端口扫描检测
- 异常连接监控
- DDoS 攻击检测

## 🎯 优势对比

| 特性       | Cilium/eBPF | 传统 C 实现 |
| ---------- | ----------- | ----------- |
| 开发效率   | ✅ 高        | ❌ 低        |
| 类型安全   | ✅ 是        | ❌ 否        |
| 内存安全   | ✅ 是        | ❌ 手动管理  |
| 错误处理   | ✅ 统一      | ❌ 复杂      |
| 维护成本   | ✅ 低        | ❌ 高        |
| 调试便利性 | ✅ 好        | ❌ 困难      |

## 🔍 使用场景

### 1. 网络监控
```go
monitor, _ := ebpf.NewNetworkMonitor()
monitor.AttachToInterface("eth0")
monitor.StartEventProcessing()

// 每5秒打印统计信息
ticker := time.NewTicker(5 * time.Second)
for range ticker.C {
    stats, _ := monitor.GetPacketStats()
    fmt.Printf("RX: %d packets\n", stats["rx_packets"])
}
```

### 2. 安全分析
```go
// 设置端口扫描检测阈值
monitor.SetSecurityConfig(0, 10) // 10个端口/秒触发告警

// 处理安全事件
// 事件会通过 Ring Buffer 异步传递
```

### 3. 性能分析
```go
flowStats, _ := monitor.GetFlowStats()
for flow, count := range flowStats {
    fmt.Printf("Flow %s: %d packets\n", flow, count)
}
```

## 🛠️ 开发指南

### 扩展新功能

1. **添加新的 Map**：
```go
func (nm *NetworkMonitor) createCustomMap() error {
    nm.customMap, err = ebpf.NewMap(&ebpf.MapSpec{
        Type:       ebpf.Hash,
        KeySize:    4,
        ValueSize:  8,
        MaxEntries: 1024,
        Name:       "custom_map",
    })
    return err
}
```

2. **添加事件处理**：
```go
func (nm *NetworkMonitor) handleCustomEvent(event *CustomEvent) {
    // 处理自定义事件逻辑
}
```

### 性能优化

1. **Ring Buffer 大小**：根据流量调整缓冲区大小
2. **Map 容量**：合理设置 MaxEntries 避免哈希冲突
3. **事件频率**：控制统计读取频率
4. **资源清理**：及时释放不用的资源

## 🔐 安全注意事项

- ⚠️ 需要 root 权限运行
- ⚠️ 确保内核版本兼容性
- ⚠️ 监控资源使用情况
- ⚠️ 处理所有错误边界情况

## 📚 学习资源

- [eBPF 官方文档](https://ebpf.io/)
- [Cilium/eBPF 库文档](https://pkg.go.dev/github.com/cilium/ebpf)
- [Kubernetes 网络概念](https://kubernetes.io/docs/concepts/cluster-administration/networking/)

---

通过这个清理后的实现，你可以专注于学习 eBPF 的核心概念，而不被复杂的实现细节干扰。项目现在更加简洁、高效，完全基于 Go 语言生态，为学习和生产使用都提供了良好的基础。
