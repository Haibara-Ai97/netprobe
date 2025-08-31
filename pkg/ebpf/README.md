# eBPF Package

这个包提供了一个结构化的 eBPF 网络监控框架，使用 `bpf2go` 生成的代码来加载和管理 eBPF 程序。

## 快速开始

### 基本使用

```go
package main

import (
    "log"
    "time"
    "github.com/Haibara-Ai97/netprobe/pkg/ebpf"
)

func main() {
    // 创建管理器
    manager := ebpf.NewManager()
    defer manager.Close()

    // 加载 eBPF 程序
    if err := manager.LoadNetworkMonitor(); err != nil {
        log.Fatal("Failed to load eBPF programs:", err)
    }

    // 附加到网络接口
    if err := manager.AttachNetworkMonitor("eth0"); err != nil {
        log.Fatal("Failed to attach to interface:", err)
    }

    // 监控 30 秒
    time.Sleep(30 * time.Second)

    // 获取统计信息
    if stats, err := manager.GetGlobalStats(); err == nil {
        log.Printf("Network Stats: %s", stats.String())
    }
}
```

### 高级配置

```go
// 创建自定义配置
config := ebpf.DefaultManagerConfig()
config.XDPMode = ebpf.XDPAdvancedFilter
config.EnableSecurityAlerts = true
config.EnableDetailedEvents = true

// 使用配置创建管理器
manager := ebpf.NewManagerWithConfig(config)
```

## 文件说明

### 核心文件

- **`manager.go`**: 高级管理接口，提供统一的 eBPF 程序管理
- **`loader.go`**: 底层 eBPF 程序加载和附加逻辑
- **`event_handlers.go`**: 事件处理器实现
- **`types.go`**: 类型定义和接口
- **`ringbuffer.go`**: Ring Buffer 数据处理
- **`utils.go`**: 工具函数

### 支持文件

- **`ARCHITECTURE.md`**: 详细的架构文档
- **`network_loader_test.go`**: 测试文件

## 主要特性

### 1. 分层架构
- **Manager**: 高级管理接口
- **NetworkLoader**: eBPF 程序加载器
- **EventHandlers**: 事件处理逻辑
- **RingBuffer**: 数据流处理

### 2. 多种 XDP 模式
- **Basic Monitor**: 基础网络监控
- **Advanced Filter**: 高级过滤和安全检测
- **Load Balancer**: 负载均衡功能

### 3. 事件处理
- **安全事件**: DDoS 检测、异常检测
- **负载均衡**: 流量分发统计
- **统计事件**: 网络流量统计

### 4. 实时监控
- Ring Buffer 批处理
- 实时统计报告
- 黑名单管理

## API 文档

### Manager 接口

```go
// 基本操作
manager := NewManager()
err := manager.LoadNetworkMonitor()
err := manager.AttachNetworkMonitor("eth0")
err := manager.DetachNetworkMonitor()
manager.Close()

// 统计信息
stats, err := manager.GetGlobalStats()
secStats, err := manager.GetSecurityStats()
lbStats, err := manager.GetLoadBalancerStats()

// 黑名单管理
err := manager.AddIPToBlacklist("192.168.1.100")
err := manager.RemoveIPFromBlacklist("192.168.1.100")
ips, err := manager.GetBlacklistedIPs()

// 配置管理
manager.UpdateConfig(newConfig)
config := manager.GetConfig()
```

### 配置选项

```go
type ManagerConfig struct {
    XDPMode              XDPProgramType // XDP 程序类型
    EnableXDPEvents      bool           // 启用 XDP 事件
    EnableTCEvents       bool           // 启用 TC 事件
    EnableDetailedEvents bool           // 启用详细事件
    BatchSize            int            // 批处理大小
    BatchTimeout         time.Duration  // 批处理超时
    StatsReportInterval  time.Duration  // 统计报告间隔
    EnableSecurityAlerts bool           // 启用安全告警
}
```

## 系统要求

- Linux 内核 5.4+ (支持 eBPF)
- CAP_BPF 或 root 权限
- 支持 XDP 的网络接口

## 错误处理

包提供了完整的错误处理机制：

```go
// 检查系统支持
if !ebpf.IsSupported() {
    log.Fatal("eBPF is not supported on this system")
}

// 错误处理示例
if err := manager.LoadNetworkMonitor(); err != nil {
    log.Printf("Failed to load programs: %v", err)
    return
}
```

## 性能考虑

- Ring Buffer 使用批处理减少系统调用
- 事件处理器并行处理
- 内存映射减少数据拷贝
- 自动清理过期数据

## 调试

启用详细日志以获取更多调试信息：

```go
config := ebpf.DefaultManagerConfig()
config.EnableDetailedEvents = true
```

查看详细架构文档：[ARCHITECTURE.md](./ARCHITECTURE.md)
    fmt.Println(stats.String())
}
```

### 2. 使用 Manager

```go
package main

import (
    "github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
    manager := ebpf.NewManager()
    defer manager.Close()

    // 检查支持
    if !ebpf.IsSupported() {
        panic("eBPF not supported")
    }

    // 加载网络监控
    if err := manager.LoadNetworkMonitor(); err != nil {
        panic(err)
    }

    // 附加到接口
    if err := manager.AttachNetworkMonitor("eth0"); err != nil {
        panic(err)
    }

    // 获取统计
    stats, err := manager.GetNetworkStats()
    if err != nil {
        panic(err)
    }
    
    for name, value := range stats {
        fmt.Printf("%s: %d\n", name, value)
    }
}
```

## 编译要求

1. 确保已生成 bpf2go 代码：
```bash
cd ebpf/network
go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" --target=amd64 NetworkMonitor monitor.c
```

2. 确保 C 编译环境：
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm

# RHEL/CentOS
sudo yum install clang llvm
```

## 数据结构

### GlobalStats
全局网络统计信息：
- `RxPackets`: 接收的数据包数量
- `TxPackets`: 发送的数据包数量  
- `RxBytes`: 接收的字节数
- `TxBytes`: 发送的字节数
- `Timestamp`: 统计时间戳

### FlowKey
流量键，用于标识网络流：
- `SrcIP`: 源 IP 地址
- `DstIP`: 目标 IP 地址
- `SrcPort`: 源端口
- `DstPort`: 目标端口
- `Protocol`: 协议类型

### TCDeviceKey
TC 设备统计键：
- `Ifindex`: 网络接口索引
- `Direction`: 方向 (0=ingress, 1=egress)
- `StatType`: 统计类型 (0=packets, 1=bytes)

## 注意事项

1. 需要 root 权限运行
2. 确保内核支持 eBPF
3. TC 程序需要手动设置 qdisc 和 filter
4. XDP 程序会自动附加到指定接口

## 故障排除

如果遇到加载问题：

1. 检查内核版本：
```bash
uname -r
```

2. 检查 eBPF 支持：
```bash
cat /proc/config.gz | gunzip | grep BPF
```

3. 检查权限：
```bash
id  # 确保是 root 用户
```

4. 查看内核日志：
```bash
dmesg | tail
```
