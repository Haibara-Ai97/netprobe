# VXLAN 流量监控 - Flannel Kubernetes 网络监控

这个模块提供了专门用于监控Kubernetes集群中Flannel框架Pod间VXLAN流量的eBPF程序。

## 功能特性

### 核心功能
- **VXLAN流量监控**: 监控Flannel VXLAN封装/解封装流量
- **Pod间通信追踪**: 跟踪Kubernetes Pod之间的网络流量
- **实时统计**: 提供数据包和字节级别的实时统计
- **多维度分析**: 支持按VNI、接口、流等多个维度统计

### 监控维度
1. **流量流(Flow)统计**:
   - 外层IP (宿主机IP)
   - 内层IP (Pod IP)
   - VXLAN网络标识符 (VNI)
   - 协议类型和端口信息
   - 封装/解封装分别统计

2. **接口统计**:
   - 每个网络接口的VXLAN流量
   - 数据包数量和字节数

3. **VXLAN网络统计**:
   - 每个VNI的流量统计
   - 网络级别的性能分析

4. **Pod信息映射**:
   - Pod IP到节点IP的映射
   - Pod名称和命名空间信息
   - 创建时间跟踪

## 技术实现

### eBPF程序结构

#### 内核侧程序 (`ebpf/vxlan/monitor.c`)
- **TC Ingress Hook**: 监控VXLAN解封装流量
- **TC Egress Hook**: 监控VXLAN封装流量
- **VXLAN协议解析**: 解析VXLAN头部和内层数据包
- **多层映射**: 流量统计、接口统计、VNI统计等多个eBPF映射

#### 用户态程序 (`pkg/ebpf/vxlan_loader.go`)
- **程序加载管理**: 管理eBPF程序的加载和卸载
- **事件处理**: 处理Ring Buffer中的实时事件
- **统计数据获取**: 提供统计数据的读取接口
- **Pod信息管理**: 管理Pod元数据信息

### 数据结构

```c
// VXLAN流量标识
struct vxlan_flow_key {
    __u32 outer_src_ip;    // 外层源IP (宿主机IP)
    __u32 outer_dst_ip;    // 外层目标IP (宿主机IP)
    __u32 inner_src_ip;    // 内层源IP (Pod IP)
    __u32 inner_dst_ip;    // 内层目标IP (Pod IP)
    __u32 vni;             // VXLAN网络标识符
    __u16 inner_src_port;  // 内层源端口
    __u16 inner_dst_port;  // 内层目标端口
    __u8  inner_proto;     // 内层协议
    __u8  direction;       // 流量方向
};

// VXLAN流量统计
struct vxlan_flow_stats {
    __u64 packets;         // 数据包数量
    __u64 bytes;           // 字节数
    __u64 first_seen;      // 首次观察时间
    __u64 last_seen;       // 最后观察时间
    __u32 encap_packets;   // 封装数据包数
    __u32 decap_packets;   // 解封装数据包数
    __u64 encap_bytes;     // 封装字节数
    __u64 decap_bytes;     // 解封装字节数
};
```

## 使用方法

### 1. 编译eBPF程序

```bash
cd /workspace/netprobe/ebpf/vxlan
go generate
```

这将生成：
- `vxlanmonitor_x86_bpfel.o`: 编译后的eBPF字节码
- `vxlanmonitor_x86_bpfel.go`: Go语言绑定代码

### 2. 编译示例程序

```bash
cd /workspace/netprobe
go build -o bin/vxlan_monitor examples/vxlan_monitor.go
```

### 3. 运行监控程序

```bash
# 假设Flannel使用flannel.1接口
sudo ./bin/vxlan_monitor flannel.1
```

### 4. 手动附加TC程序 (可选)

由于TC程序附加需要特殊权限，您可能需要手动附加：

```bash
# 添加clsact qdisc
sudo tc qdisc add dev flannel.1 clsact

# 附加ingress程序
sudo tc filter add dev flannel.1 ingress bpf obj ebpf/vxlan/vxlanmonitor_x86_bpfel.o sec tc/ingress

# 附加egress程序  
sudo tc filter add dev flannel.1 egress bpf obj ebpf/vxlan/vxlanmonitor_x86_bpfel.o sec tc/egress
```

### 5. 查看监控结果

程序运行后会显示：
- 实时VXLAN事件
- 流量统计信息
- 接口和VNI级别的统计

## 在Kubernetes环境中的部署

### 前置条件
1. Kubernetes集群使用Flannel网络插件
2. 节点内核支持eBPF和TC hooks (内核版本 >= 4.9)
3. 节点上安装了clang和llvm工具链

### 部署步骤

1. **识别Flannel接口**:
   ```bash
   # 查找Flannel VXLAN接口
   ip link show | grep flannel
   # 通常是 flannel.1
   ```

2. **创建DaemonSet配置**:
   ```yaml
   apiVersion: apps/v1
   kind: DaemonSet
   metadata:
     name: vxlan-monitor
     namespace: kube-system
   spec:
     selector:
       matchLabels:
         name: vxlan-monitor
     template:
       metadata:
         labels:
           name: vxlan-monitor
       spec:
         hostNetwork: true
         containers:
         - name: vxlan-monitor
           image: netprobe:vxlan
           securityContext:
             privileged: true
           env:
           - name: INTERFACE
             value: "flannel.1"
           volumeMounts:
           - name: sys
             mountPath: /sys
             readOnly: true
           - name: debug
             mountPath: /sys/kernel/debug
         volumes:
         - name: sys
           hostPath:
             path: /sys
         - name: debug
           hostPath:
             path: /sys/kernel/debug
   ```

3. **构建容器镜像**:
   ```dockerfile
   FROM ubuntu:22.04
   RUN apt-get update && apt-get install -y \
       clang llvm libbpf-dev linux-headers-generic
   COPY bin/vxlan_monitor /usr/local/bin/
   COPY ebpf/vxlan/vxlanmonitor_x86_bpfel.o /opt/ebpf/
   ENTRYPOINT ["/usr/local/bin/vxlan_monitor"]
   ```

## 监控指标

### 流量指标
- **数据包数量**: 总数据包数、封装数据包数、解封装数据包数
- **字节数**: 总字节数、封装字节数、解封装字节数
- **时间戳**: 首次观察时间、最后观察时间

### 性能指标
- **流量密度**: 每个VNI的流量分布
- **Pod通信模式**: Pod间通信频率和模式
- **网络热点**: 高流量的Pod和节点

### 异常检测
- **新连接检测**: 新建的Pod间连接
- **流量异常**: 异常大的数据包或流量突增
- **协议分布**: 不同协议的流量分布

## 故障排除

### 常见问题

1. **权限错误**:
   ```
   Error: failed to load VXLAN eBPF program: permission denied
   ```
   解决：确保以root权限运行，并且内核支持eBPF

2. **接口不存在**:
   ```
   Error: failed to get interface flannel.1: no such device
   ```
   解决：检查Flannel是否正确安装，确认接口名称

3. **TC附加失败**:
   ```
   Error: failed to attach TC program
   ```
   解决：手动使用tc命令附加程序，或检查内核TC支持

### 调试建议

1. **检查eBPF程序状态**:
   ```bash
   sudo bpftool prog list
   sudo bpftool map list
   ```

2. **检查TC配置**:
   ```bash
   sudo tc qdisc show dev flannel.1
   sudo tc filter show dev flannel.1 ingress
   sudo tc filter show dev flannel.1 egress
   ```

3. **查看内核日志**:
   ```bash
   sudo dmesg | grep -i bpf
   sudo dmesg | grep -i tc
   ```

## 性能考虑

### eBPF程序优化
- 使用高效的数据结构和算法
- 避免在热路径上执行复杂操作
- 合理设置映射大小限制

### 内存使用
- Ring Buffer大小: 16MB (可调整)
- 流量映射: 最多65536个流
- Pod信息映射: 最多10240个Pod

### CPU影响
- eBPF程序在内核中执行，CPU开销很小
- 主要开销在用户态的事件处理
- 建议根据流量大小调整统计报告间隔

## 扩展功能

### 未来增强
1. **Prometheus集成**: 导出监控指标到Prometheus
2. **告警功能**: 基于阈值的自动告警
3. **可视化界面**: Web界面显示流量拓扑
4. **历史数据**: 长期流量趋势分析
5. **多租户支持**: 基于命名空间的隔离监控

### 自定义开发
代码结构清晰，支持以下自定义：
- 添加新的统计维度
- 扩展事件处理逻辑
- 集成其他网络插件
- 添加自定义过滤规则

## 参考资料

- [eBPF编程指南](https://ebpf.io/)
- [Cilium eBPF库文档](https://pkg.go.dev/github.com/cilium/ebpf)
- [Linux TC子系统](https://man7.org/linux/man-pages/man8/tc.8.html)
- [Flannel网络原理](https://github.com/flannel-io/flannel)
- [VXLAN协议规范](https://tools.ietf.org/html/rfc7348)
