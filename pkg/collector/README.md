# TC Collector

TC Collector 是一个用于收集 Linux TC (Traffic Control) 层网络流量统计的 Go 包。它基于 eBPF 技术，能够高效地收集每个网络接口的入站和出站流量数据。

## 特性

- **实时流量监控**: 收集每个网络接口的包数和字节数统计
- **速率计算**: 自动计算包速率和字节速率（每秒）
- **多接口支持**: 同时监控系统中的所有网络接口
- **灵活的收集间隔**: 可配置的数据收集频率
- **丰富的统计信息**: 提供详细的接口统计和摘要信息
- **过滤和排序**: 支持按活跃度、速率等条件过滤和排序接口

## 核心组件

### 1. TCCollector
负责从 eBPF maps 中读取 TC 层的统计数据，并计算速率信息。

### 2. Manager
管理收集器的生命周期，支持周期性数据收集。

### 3. InterfaceStats
表示单个网络接口的统计信息，包括：
- 接口名称和索引
- 入站/出站包数和字节数
- 入站/出站包速率和字节速率
- 最后更新时间

## 使用示例

### 基本使用

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/your-org/kube-net-probe/pkg/collector"
    "github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
    // 1. 创建 eBPF 管理器
    ebpfManager := ebpf.NewManager()
    
    // 2. 加载网络监控程序
    if err := ebpfManager.LoadNetworkMonitor(); err != nil {
        log.Fatalf("Failed to load network monitor: %v", err)
    }
    defer ebpfManager.Close()
    
    // 3. 创建收集器管理器
    collectorManager := collector.NewManager(ebpfManager)
    
    // 4. 设置收集间隔
    collectorManager.SetCollectInterval(5 * time.Second)
    
    // 5. 启动收集器
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    resultChan := collectorManager.Start(ctx)
    
    // 6. 处理收集结果
    for result := range resultChan {
        if result.Error != nil {
            log.Printf("Collection error: %v", result.Error)
            continue
        }
        
        // 创建摘要
        summary := collector.SummarizeCollection(result.Stats, 5)
        fmt.Println(summary.String())
        
        // 显示活跃接口
        activeStats := collector.FilterActiveInterfaces(result.Stats)
        for _, stat := range activeStats {
            fmt.Printf("  %s\n", stat.Summary())
        }
    }
}
```

### 单次收集

```go
func collectOnce(ebpfManager *ebpf.Manager) {
    tcCollector := collector.NewTCCollector(ebpfManager)
    
    stats, err := tcCollector.CollectOnce()
    if err != nil {
        log.Printf("Collection failed: %v", err)
        return
    }
    
    fmt.Printf("Collected stats for %d interfaces\n", len(stats))
    for _, stat := range stats {
        if stat.HasTraffic() {
            fmt.Println(stat.String())
        }
    }
}
```

### 监控特定接口

```go
func monitorInterface(ebpfManager *ebpf.Manager, interfaceName string) {
    collectorManager := collector.NewManager(ebpfManager)
    collectorManager.SetCollectInterval(2 * time.Second)
    
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()
    
    resultChan := collectorManager.Start(ctx)
    
    for result := range resultChan {
        if result.Error != nil {
            continue
        }
        
        // 查找目标接口
        for _, stat := range result.Stats {
            if stat.InterfaceName == interfaceName {
                fmt.Printf("[%s] %s\n",
                    result.Timestamp.Format("15:04:05"),
                    stat.Summary())
                break
            }
        }
    }
}
```

## 数据结构

### InterfaceStats

```go
type InterfaceStats struct {
    InterfaceName      string    // 接口名称 (如 "eth0")
    InterfaceIndex     uint32    // 接口索引
    IngressPackets     uint64    // 入站包数
    IngressBytes       uint64    // 入站字节数
    EgressPackets      uint64    // 出站包数
    EgressBytes        uint64    // 出站字节数
    IngressPacketsRate float64   // 入站包速率 (包/秒)
    IngressBytesRate   float64   // 入站字节速率 (字节/秒)
    EgressPacketsRate  float64   // 出站包速率 (包/秒)
    EgressBytesRate    float64   // 出站字节速率 (字节/秒)
    LastUpdated        time.Time // 最后更新时间
}
```

### CollectionResult

```go
type CollectionResult struct {
    Stats     []InterfaceStats  // 接口统计数组
    Error     error            // 收集错误
    Timestamp time.Time        // 收集时间戳
}
```

## 实用函数

### 格式化函数

- `FormatBytes(bytes uint64) string`: 格式化字节数 (如 "1.50 MB")
- `FormatPacketRate(packetsPerSec float64) string`: 格式化包速率
- `FormatBytesRate(bytesPerSec float64) string`: 格式化字节速率

### 过滤和排序

- `FilterActiveInterfaces(stats []InterfaceStats) []InterfaceStats`: 过滤活跃接口
- `FilterInterfacesByName(stats []InterfaceStats, names []string) []InterfaceStats`: 按名称过滤
- `SortInterfacesByBytesRate(stats []InterfaceStats, descending bool)`: 按字节速率排序
- `SortInterfacesByPacketsRate(stats []InterfaceStats, descending bool)`: 按包速率排序

### 摘要功能

- `SummarizeCollection(stats []InterfaceStats, topN int) *CollectionSummary`: 创建收集摘要

## 配置选项

### 收集间隔
```go
// 设置收集间隔为 3 秒
collectorManager.SetCollectInterval(3 * time.Second)
```

### 活跃阈值
接口被认为"活跃"的阈值是每秒 0.1 包。这可以通过修改 `InterfaceStats.HasActivity()` 方法来调整。

## 性能考虑

- **低开销**: 基于 eBPF，对系统性能影响极小
- **内存效率**: 使用原子操作更新统计，避免锁竞争
- **可扩展**: 支持同时监控多个网络接口
- **实时性**: 提供实时的流量统计和速率计算

## 错误处理

收集器会处理以下错误情况：
- eBPF 程序未加载
- 网络接口映射失败
- Map 读取错误
- 上下文取消

所有错误都会通过 `CollectionResult.Error` 字段返回，不会导致程序崩溃。

## 测试

运行测试：
```bash
go test ./pkg/collector/...
```

包含的测试：
- 枚举类型测试
- 接口统计方法测试
- 格式化函数测试
- 摘要和过滤功能测试

## 集成指南

TC Collector 设计为与 Prometheus metrics 导出器集成使用：

1. **收集数据**: 使用 TC Collector 定期收集接口统计
2. **转换格式**: 将统计数据转换为 Prometheus metrics 格式
3. **HTTP 暴露**: 通过 HTTP 端点暴露 `/metrics`

这为网络监控提供了完整的可观测性解决方案。
