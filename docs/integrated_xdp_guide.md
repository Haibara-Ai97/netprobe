# NetProbe XDP 集成管理系统

本文档介绍如何使用NetProbe的集成eBPF管理系统，该系统将XDP的流量统计、安全检测和负载均衡功能整合到统一的管理接口中。

## 功能特性

### 1. 统一的eBPF管理
- 单一Manager管理所有eBPF程序
- 自动程序加载和卸载
- 统一的配置管理
- 集成的事件处理

### 2. XDP多模式支持
- **基础监控模式**: 高性能数据包统计
- **安全过滤模式**: DDoS防护和威胁检测
- **负载均衡模式**: 基于哈希的流量分发

### 3. 实时事件处理
- 零拷贝Ring Buffer机制
- 批量事件处理
- 自定义事件处理器
- 组合式处理器架构

### 4. 安全特性
- IP黑名单管理
- 速率限制
- 异常检测
- 自动威胁响应

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
    // 检查eBPF支持
    if !ebpf.IsSupported() {
        log.Fatal("eBPF not supported")
    }

    // 创建管理器
    manager := ebpf.NewManager()
    defer manager.Close()

    // 加载eBPF程序
    if err := manager.LoadNetworkMonitor(); err != nil {
        log.Fatal("Failed to load programs:", err)
    }

    // 附加到网络接口
    if err := manager.AttachNetworkMonitor("eth0"); err != nil {
        log.Fatal("Failed to attach:", err)
    }

    // 运行监控
    time.Sleep(30 * time.Second)

    // 获取统计信息
    stats, _ := manager.GetGlobalStats()
    log.Printf("Processed: %d packets, %d bytes", 
        stats.RxPackets, stats.RxBytes)
}
```

### 高级配置

```go
// 创建自定义配置
config := &ebpf.ManagerConfig{
    XDPMode:              ebpf.XDPAdvancedFilter,
    EnableXDPEvents:      true,
    EnableTCEvents:       true,
    EnableDetailedEvents: true,
    BatchSize:            200,
    BatchTimeout:         50 * time.Millisecond,
    StatsReportInterval:  30 * time.Second,
    EnableSecurityAlerts: true,
}

// 使用自定义配置创建管理器
manager := ebpf.NewManagerWithConfig(config)
```

## XDP模式详解

### 1. 基础监控模式 (XDPBasicMonitor)

```go
// 切换到基础监控模式
manager.SwitchXDPMode(ebpf.XDPBasicMonitor)

// 运行基础监控演示
manager.DemoBasicMonitoring("eth0", 30*time.Second)

// 获取统计信息
stats, err := manager.GetGlobalStats()
if err == nil {
    log.Printf("RX: %d packets, TX: %d packets", 
        stats.RxPackets, stats.TxPackets)
}
```

**特性:**
- 高性能数据包统计
- 最小CPU开销
- 基础流量分析
- 接口级别统计

### 2. 安全过滤模式 (XDPAdvancedFilter)

```go
// 切换到安全模式
manager.SwitchXDPMode(ebpf.XDPAdvancedFilter)

// 运行安全演示
manager.DemoSecurityFiltering("eth0", 30*time.Second)

// 添加IP到黑名单
manager.AddIPToBlacklist("192.168.1.100")

// 获取安全统计
secStats, err := manager.GetSecurityStats()
if err == nil {
    log.Printf("DDoS blocked: %d, Security events: %d", 
        secStats.DDosBlocked, secStats.SecurityEvents)
}

// 查看黑名单
blacklisted, _ := manager.GetBlacklistedIPs()
log.Printf("Blacklisted IPs: %v", blacklisted)
```

**安全特性:**
- DDoS攻击防护
- 速率限制 (1ms间隔)
- IP黑名单管理
- 可疑数据包检测
- ICMP洪水防护
- 自动黑名单过期 (60秒)

### 3. 负载均衡模式 (XDPLoadBalancer)

```go
// 切换到负载均衡模式
manager.SwitchXDPMode(ebpf.XDPLoadBalancer)

// 运行负载均衡演示
manager.DemoLoadBalancing("eth0", 30*time.Second)

// 获取负载均衡统计
lbStats, err := manager.GetLoadBalancerStats()
if err == nil {
    log.Printf("Load balancer decisions: %d", lbStats.LBDecisions)
    for target, count := range lbStats.TargetCounts {
        percentage := float64(count) / float64(lbStats.LBDecisions) * 100
        log.Printf("Target %d: %.1f%%", target, percentage)
    }
}
```

**负载均衡特性:**
- 基于5元组哈希分发
- 流一致性保证
- 4路负载分发
- 实时负载统计
- 目标接口监控

## 事件处理系统

### 自定义事件处理器

```go
// 实现EventHandler接口
type CustomHandler struct{}

func (h *CustomHandler) HandleEvent(event *ebpf.NetworkEvent) error {
    // 处理单个事件
    if event.EventType == ebpf.EventTypeSecurity {
        log.Printf("Security event from %s", 
            uint32ToIPString(event.SrcIP))
    }
    return nil
}

func (h *CustomHandler) HandleBatch(events []*ebpf.NetworkEvent) error {
    // 处理批量事件
    for _, event := range events {
        h.HandleEvent(event)
    }
    return nil
}

// 添加到管理器
manager.GetNetworkLoader().AddEventHandler(&CustomHandler{})
```

### 预置事件处理器

系统提供了几个预置的事件处理器:

1. **SecurityEventHandler**: 安全事件处理
2. **LoadBalancerEventHandler**: 负载均衡事件处理  
3. **StatisticsEventHandler**: 统计事件处理
4. **CompositeEventHandler**: 组合多个处理器

## 统计信息API

### 全局统计
```go
stats, err := manager.GetGlobalStats()
// 包含: RxPackets, TxPackets, RxBytes, TxBytes
```

### 安全统计
```go
secStats, err := manager.GetSecurityStats()  
// 包含: DDosBlocked, SecurityEvents, XDPDropped, BlacklistedIPs
```

### 负载均衡统计
```go
lbStats, err := manager.GetLoadBalancerStats()
// 包含: LBDecisions, TargetCounts
```

### 流统计
```go
flowStats, err := manager.GetFlowStats()
// 包含: 每个流的数据包计数
```

### TC设备统计
```go
tcStats, err := manager.GetTCDeviceStats()
// 包含: 每个接口的ingress/egress统计
```

### Ring Buffer统计
```go
rbStats := manager.GetRingBufferStats()
// 包含: events_read, events_dropped, batches_processed
```

## 管理操作

### 黑名单管理
```go
// 添加IP到黑名单
manager.AddIPToBlacklist("192.168.1.100")

// 移除IP从黑名单
manager.RemoveIPFromBlacklist("192.168.1.100")

// 获取黑名单列表
blacklisted, _ := manager.GetBlacklistedIPs()

// 清理过期黑名单条目
manager.ClearExpiredBlacklist()
```

### 统计重置
```go
// 重置所有统计信息
manager.ResetStatistics()
```

### 配置更新
```go
// 获取当前配置
config := manager.GetConfig()

// 更新配置
config.EnableSecurityAlerts = false
manager.UpdateConfig(config)
```

## 运行示例

### 编译和运行主程序
```bash
cd cmd/netprobe-xdp
go build -o netprobe-xdp main.go

# 基础监控
sudo ./netprobe-xdp -interface=eth0 -mode=basic

# 安全过滤
sudo ./netprobe-xdp -interface=eth0 -mode=security

# 负载均衡
sudo ./netprobe-xdp -interface=eth0 -mode=loadbalancer

# 演示模式
sudo ./netprobe-xdp -interface=eth0 -mode=security -demo -duration=60s

# 重置统计
sudo ./netprobe-xdp -reset
```

### 运行集成演示
```bash
cd examples
go run integrated_demo.go
```

## 性能特性

### Ring Buffer零拷贝
- 1MB Ring Buffer大小
- 零拷贝事件传输
- 批量处理优化
- 自动丢包处理

### 原子操作
- 线程安全的统计更新
- 无锁数据结构
- 高并发支持

### 内存优化
- 自动内存限制移除
- LRU缓存机制
- 过期条目自动清理

## 注意事项

1. **权限要求**: 需要root权限加载eBPF程序
2. **内核版本**: 需要Linux内核4.18+支持XDP
3. **网络接口**: 确保目标接口存在且可访问
4. **TC支持**: TC程序需要clsact qdisc支持

## 故障排除

### 常见问题

1. **程序加载失败**
   ```bash
   # 检查内核版本和eBPF支持
   uname -r
   zgrep CONFIG_BPF /proc/config.gz
   ```

2. **TC附加失败**
   ```bash
   # 添加clsact qdisc
   sudo tc qdisc add dev eth0 clsact
   ```

3. **权限错误**
   ```bash
   # 使用sudo运行程序
   sudo ./your-program
   ```

4. **接口不存在**
   ```bash
   # 查看可用接口
   ip link show
   ```

## 架构优势

通过整合XDP功能到统一的管理系统中，我们实现了:

1. **简化的API**: 单一接口管理所有XDP功能
2. **配置灵活性**: 运行时模式切换
3. **事件统一**: 所有事件通过同一套处理器
4. **资源管理**: 自动资源清理和生命周期管理
5. **扩展性**: 易于添加新的XDP程序和处理器

这种设计使得NetProbe成为一个强大而易用的网络监控和安全平台。
