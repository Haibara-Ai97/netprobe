# 新的eBPF架构设计

## 架构概述

重新设计的eBPF架构采用了清晰的分层设计，将ringbuffer reader、事件处理器和查询接口分离，提供了更好的可维护性和扩展性。

## 核心组件

### 1. 事件处理器 (Event Handlers)

每个钩子点都有专门的事件处理器：

#### XDPHandler
- **文件**: `event_handlers.go`
- **职责**: 处理XDP钩子点的事件
- **支持钩子**: `HookXDP`
- **特性**: 
  - 独立的流量统计
  - 可配置的详细日志
  - 线程安全的统计更新

#### TCHandler
- **文件**: `event_handlers.go`  
- **职责**: 处理TC钩子点的事件
- **支持钩子**: `HookTCIngress`, `HookTCEgress`
- **特性**:
  - 分别统计ingress和egress流量
  - 支持合并统计查询
  - 可配置方向跟踪

#### SecurityHandler
- **文件**: `event_handlers.go`
- **职责**: 处理安全相关事件
- **支持钩子**: 所有钩子点
- **特性**:
  - 异常检测和告警
  - IP白/黑名单管理
  - 可配置告警阈值

### 2. 查询接口 (Query Interfaces)

每个事件处理器都提供对应的查询接口：

```go
type QueryInterface interface {
    GetTotalStats() *TrafficStats
    GetHookStats(hook HookPoint) *TrafficStats
    GetProtocolDistribution() map[uint8]uint64
    GetPortStats() map[uint16]uint64
    ResetStats()
}
```

#### 查询接口实现
- **XDPQueryInterface**: XDP统计查询
- **TCQueryInterface**: TC统计查询，支持ingress/egress分别查询
- **SecurityQueryInterface**: 安全统计查询

### 3. 管理器 (Manager)

#### SimpleEBPFManager
- **文件**: `simple_manager.go`
- **职责**: 统一管理eBPF程序生命周期和事件处理器
- **特性**:
  - 根据配置自动注册处理器
  - 统一的查询接口
  - 自动统计报告
  - 线程安全的操作

## 数据流

```
eBPF程序 -> RingBuffer -> NetworkLoader -> EventHandlers -> 统计信息
                                                    |
用户查询 <- QueryInterface <- Manager <---------
```

### 数据流程详解

1. **事件产生**: eBPF程序在内核中捕获网络事件
2. **事件传输**: 通过RingBuffer将事件传输到用户空间
3. **事件读取**: NetworkLoader从RingBuffer读取事件
4. **事件分发**: NetworkLoader将事件分发给注册的处理器
5. **事件处理**: 各处理器根据钩子点和事件类型处理事件
6. **统计更新**: 处理器更新内部统计信息
7. **用户查询**: 通过Manager和QueryInterface查询统计信息

## 主要改进

### 1. 清晰的职责分离
- **事件处理器**: 专注于特定钩子点的事件处理和统计
- **查询接口**: 提供统一的数据查询方式
- **管理器**: 统一管理组件生命周期

### 2. 按钩子点设计
- 每个钩子点有专门的处理器
- 支持独立的统计和查询
- 便于添加新的钩子点支持

### 3. 用户配置驱动
- 根据用户配置注册相应的处理器
- 灵活的功能启用/禁用
- 可配置的日志和告警

### 4. 线程安全
- 所有统计操作都使用读写锁保护
- 支持并发查询和更新
- 避免数据竞争

## 使用示例

### 基本使用

```go
// 创建管理器
manager := NewSimpleEBPFManager()
defer manager.Close()

// 加载eBPF程序
if err := manager.LoadNetworkMonitor(); err != nil {
    log.Fatal("Failed to load eBPF programs:", err)
}

// 附加到网络接口
if err := manager.AttachNetworkMonitor("eth0"); err != nil {
    log.Fatal("Failed to attach to interface:", err)
}

// 查询XDP统计
xdpStats, err := manager.GetXDPStats()
if err == nil {
    log.Printf("XDP Packets: %d, Bytes: %d", 
        xdpStats.PacketCount, xdpStats.ByteCount)
}

// 查询TC Ingress统计
ingressStats, err := manager.GetTCIngressStats()
if err == nil {
    log.Printf("TC Ingress Packets: %d", ingressStats.PacketCount)
}
```

### 高级查询

```go
// 获取协议分布
protocolDist, err := manager.GetHandlerQueryInterface("TC Handler")
if err == nil {
    protocols := protocolDist.GetProtocolDistribution()
    for proto, count := range protocols {
        log.Printf("Protocol %s: %d packets", getProtocolName(proto), count)
    }
}

// 重置特定处理器的统计
if queryInterface, err := manager.GetHandlerQueryInterface("XDP Handler"); err == nil {
    queryInterface.ResetStats()
}
```

### 安全告警

```go
// 设置安全告警回调
manager.SetSecurityAlertCallback(func(event *NetworkEvent) {
    log.Printf("Security Alert: %s", event.String())
    // 自定义告警处理逻辑
})
```

## 配置选项

```go
config := &SimpleManagerConfig{
    EnabledHooks:        []HookPoint{HookXDP, HookTCIngress},
    XDPMode:             XDPAdvancedFilter,
    StatsReportInterval: 30 * time.Second,
    EnableDetailedLog:   true,
}

manager := NewSimpleEBPFManagerWithConfig(config)
```

## 扩展性

### 添加新的钩子点处理器

1. 实现 `EventHandler` 接口
2. 实现对应的 `QueryInterface`
3. 在管理器中注册处理器

### 添加新的查询功能

1. 扩展 `QueryInterface` 接口
2. 在各处理器的查询实现中添加新方法
3. 在管理器中添加便捷的查询方法

## 文件结构

```
pkg/ebpf/
├── event_handlers.go    # 事件处理器实现
├── simple_manager.go    # 简化的管理器实现
├── types.go            # 类型定义和接口
└── network_loader.go   # 网络加载器（保持原有功能）
```

这个新架构提供了清晰的分层设计，便于维护和扩展，同时保持了高性能和线程安全性。
