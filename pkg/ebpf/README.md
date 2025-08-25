# eBPF Package

这个包使用 `bpf2go` 生成的代码来加载和管理 eBPF 网络监控程序。

## 文件说明

### network_loader.go (主要组件)
使用 `bpf2go` 生成的代码来加载网络监控程序。提供：
- 类型安全的 Go 结构体
- 自动生成的 Map 和 Program 定义
- 简化的 API 接口

### manager.go
统一的管理器，提供高级的 eBPF 程序管理功能。

### example.go
使用示例和演示代码。

## 使用方法

### 1. 直接使用 NetworkLoader

```go
package main

import (
    "github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
    // 创建网络加载器
    loader := ebpf.NewNetworkLoader()
    defer loader.Close()

    // 加载程序
    if err := loader.LoadPrograms(); err != nil {
        panic(err)
    }

    // 附加到网络接口
    if err := loader.AttachNetworkPrograms("eth0"); err != nil {
        panic(err)
    }

    // 读取统计信息
    stats, err := loader.ReadGlobalStats()
    if err != nil {
        panic(err)
    }
    
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
