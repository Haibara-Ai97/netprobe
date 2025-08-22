# TC 网络监控功能

本文档描述了如何使用 eBPF TC (Traffic Control) 程序进行细粒度的网络监控。

## 🎯 功能特性

### 基础 TC 监控
- ✅ **分设备统计**: 按网络接口分别统计包数和字节数
- ✅ **双向监控**: 支持 TC ingress 和 egress 监控
- ✅ **流量分类**: 按流量五元组进行统计
- ✅ **实时事件**: 通过 RingBuf 发送详细事件到用户空间

### 收集的信息
- 📊 **基本统计**: 包数、字节数、流量速率
- 🔍 **设备信息**: 网络接口索引、队列映射
- 🏷️ **标记信息**: skb mark、priority、tc_classid
- 📦 **流量信息**: 五元组、协议类型、包大小

## 🏗️ 架构设计

```
用户空间 (Go)           内核空间 (eBPF)
┌─────────────────┐    ┌─────────────────┐
│  应用程序       │    │  TC Hook 点     │
│                 │    │                 │
│  统计收集       │◄───┤  tc_device_stats│
│  事件处理       │◄───┤  tc_events      │
│  可视化显示     │◄───┤  tc_flow_stats  │
└─────────────────┘    └─────────────────┘
```

## 📊 数据结构

### TC 设备统计键
```c
struct tc_device_key {
    __u32 ifindex;      // 网络设备索引
    __u32 direction;    // 0=ingress, 1=egress
    __u32 stat_type;    // 0=packets, 1=bytes
};
```

### TC 事件信息
```c
struct tc_event {
    __u64 timestamp;     // 时间戳
    __u32 ifindex;       // 设备索引
    __u32 direction;     // 方向
    __u32 len;           // 包长度
    __u32 mark;          // skb mark
    __u32 priority;      // 优先级
    __u32 queue_mapping; // 队列映射
    __u32 tc_classid;    // TC 类别ID
    __u8  pkt_type;      // 包类型
    struct flow_key flow; // 流量信息
};
```

## 🚀 使用方法

### 1. 编译 eBPF 程序
```bash
# 使用 Makefile
make build-ebpf

# 或使用脚本
chmod +x scripts/build_ebpf.sh
./scripts/build_ebpf.sh
```

### 2. 运行监控程序
```bash
# 编译示例程序
go build -o bin/tc_monitor examples/tc_monitor_example.go

# 运行监控 (需要 root 权限)
sudo ./bin/tc_monitor eth0
```

### 3. 查看统计信息
程序会每 5 秒显示一次统计信息：
```
📈 Traffic Statistics:
==================================================
Global Statistics:
  RX Packets  : 1234
  TX Packets  : 987
  RX Bytes    : 1.23 MB
  TX Bytes    : 987.45 KB

TC Device Statistics:
  Interface eth0:
    Ingress Packets: 567
    Ingress Bytes  : 678.90 KB
    Egress Packets : 432
    Egress Bytes   : 543.21 KB
==================================================
```

## 🔧 TC 程序附加

TC 程序需要使用 tc 命令手动附加：

### Egress 监控
```bash
# 创建 clsact qdisc
sudo tc qdisc add dev eth0 clsact

# 附加 egress 程序
sudo tc filter add dev eth0 egress bpf object-file bin/ebpf/network-monitor.o section tc
```

### Ingress 监控
```bash
# 附加 ingress 程序
sudo tc filter add dev eth0 ingress bpf object-file bin/ebpf/network-monitor.o section tc
```

### 清理
```bash
# 移除 TC 程序
sudo tc qdisc del dev eth0 clsact
```

## 📈 性能考虑

### 采样策略
- 统计信息实时更新
- 详细事件使用 1/256 采样率减少开销
- 可根据需要调整采样率

### Map 大小
- `tc_device_stats`: 1024 条目 (支持多设备)
- `tc_flow_stats`: 10240 条目 (流量统计)
- `tc_events`: 8MB RingBuf (事件缓冲)

## 🎓 学习价值

这个实现展示了对以下概念的深度理解：

### Linux 网络栈
- TC 子系统工作原理
- 包在网络栈中的路径
- QoS 和流量控制机制

### eBPF 技术
- TC Hook 点的使用
- Map 类型和数据共享
- 高效的内核编程技巧

### 系统监控
- 细粒度性能指标收集
- 实时数据处理
- 网络故障诊断

## 🚦 后续扩展

可以进一步扩展的功能：
- 队列延迟监控
- 丢包原因分析
- 带宽限制效果评估
- 流量整形监控
- 异常模式检测
