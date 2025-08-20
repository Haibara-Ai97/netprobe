# KubeNetProbe - Cilium/eBPF 实现

## 📋 概述

本项目现在专注于使用 **cilium/ebpf** 库来实现 eBPF 网络监控功能。我们已经清理了所有不必要的代码，只保留了最核心和实用的实现。

## 🗂️ 清理后的项目结构

```
pkg/ebpf/
├── go_implementation.go    # Cilium/eBPF 核心实现
├── manager.go             # eBPF 程序管理器
└── program.go             # 程序生命周期管理

examples/
└── cilium_ebpf_monitor.go # 简化的示例程序
```

## 🔧 核心组件

### 1. NetworkMonitor 主要结构

```go
type NetworkMonitor struct {
    // eBPF 程序
    xdpProgram *ebpf.Program
    tcProgram  *ebpf.Program
    
    // Maps for data storage
    packetStats    *ebpf.Map  // 数据包统计
    flowStats      *ebpf.Map  // 流量统计
    packetEvents   *ebpf.Map  // 数据包事件 Ring Buffer
    securityEvents *ebpf.Map  // 安全事件 Ring Buffer
    
    // Links for attachment
    xdpLink link.Link
    tcLink  link.Link
    
    // Event readers
    packetReader   *ringbuf.Reader
    securityReader *ringbuf.Reader
    
    // Context for graceful shutdown
    ctx    context.Context
    cancel context.CancelFunc
}
```

### 2. 关键功能

#### 创建监控器
```go
// 基础创建方式
monitor, err := ebpf.NewNetworkMonitor()

// 从对象文件创建（推荐生产环境）
monitor, err := ebpf.NewNetworkMonitorFromObjectFile("./network-monitor.o")
```

#### 附加到网络接口
```go
err := monitor.AttachToInterface("eth0")
```

#### 启动事件处理
```go
err := monitor.StartEventProcessing()
```

#### 获取统计信息
```go
packetStats, err := monitor.GetPacketStats()
flowStats, err := monitor.GetFlowStats()
```

## 🚀 快速使用

### 1. 基本用法

```go
package main

import (
    "github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
    // 创建监控器
    monitor, err := ebpf.NewNetworkMonitor()
    if err != nil {
        panic(err)
    }
    defer monitor.Close()
    
    // 附加到网络接口
    if err := monitor.AttachToInterface("eth0"); err != nil {
        panic(err)
    }
    
    // 启动事件处理
    if err := monitor.StartEventProcessing(); err != nil {
        panic(err)
    }
    
    // 程序会在这里持续运行...
}
```

### 2. 运行示例

```bash
# 运行示例程序（需要 root 权限）
sudo go run examples/cilium_ebpf_monitor.go

# 指定网络接口
sudo NETWORK_INTERFACE=wlan0 go run examples/cilium_ebpf_monitor.go
```

## 📊 数据结构

### FlowKey - 流量标识
```go
type FlowKey struct {
    SrcIP   uint32
    DstIP   uint32  
    SrcPort uint16
    DstPort uint16
    Proto   uint8
}
```

### PacketInfo - 数据包信息
```go
type PacketInfo struct {
    SrcIP      uint32
    DstIP      uint32
    SrcPort    uint16
    DstPort    uint16
    Proto      uint8
    PacketSize uint16
    Timestamp  uint64
}
```

### SecurityEvent - 安全事件
```go
type SecurityEvent struct {
    Timestamp   uint64
    EventType   uint32
    SrcIP       uint32
    DstIP       uint32
    SrcPort     uint16
    DstPort     uint16
    Proto       uint8
    Severity    uint32
    Description [64]byte
}
```

## 🔍 特性说明

### ✅ 已实现功能

1. **Map 管理**
   - Array Maps：统计计数器
   - Hash Maps：流量跟踪、连接状态
   - Ring Buffers：事件传输

2. **程序附加**
   - XDP 程序附加（网络数据包处理）
   - TC 程序附加（流量控制）

3. **事件处理**
   - 异步事件读取
   - 数据包事件处理
   - 安全事件处理

4. **统计收集**
   - 实时数据包统计
   - 流量分析
   - 性能指标

5. **资源管理**
   - 优雅的关闭机制
   - 内存限制移除
   - 错误处理和恢复

### 🔧 技术优势

1. **类型安全**：Go 语言的类型系统确保编译时错误检查
2. **内存安全**：自动垃圾回收，避免内存泄漏
3. **并发安全**：使用 context 进行优雅的协程管理
4. **错误处理**：统一的错误处理机制
5. **可扩展性**：模块化设计，易于扩展新功能

## 🛠️ 开发指南

### 添加新的 Map

```go
func (nm *NetworkMonitor) createCustomMap() error {
    var err error
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

### 添加新的事件处理

```go
func (nm *NetworkMonitor) handleCustomEvent(event *CustomEvent) {
    // 处理自定义事件
    fmt.Printf("Custom event: %+v\n", event)
}
```

### 扩展统计功能

```go
func (nm *NetworkMonitor) GetCustomStats() (map[string]uint64, error) {
    stats := make(map[string]uint64)
    // 实现自定义统计收集
    return stats, nil
}
```

## 📈 性能考虑

1. **Ring Buffer 大小**：根据流量调整 Ring Buffer 大小
2. **Map 容量**：合理设置 Map 的 MaxEntries
3. **事件处理频率**：避免过于频繁的统计读取
4. **资源清理**：及时关闭不用的资源

## 🔐 安全注意事项

1. **Root 权限**：eBPF 程序需要 root 权限运行
2. **内核兼容性**：确保内核版本 >= 4.18
3. **资源限制**：注意内存和 CPU 使用量
4. **错误边界**：处理所有可能的错误情况

这个清理后的实现专注于使用 cilium/eBPF 提供强大而简洁的网络监控功能，移除了所有不必要的复杂性，让你可以专注于学习和使用 eBPF 的核心概念。
