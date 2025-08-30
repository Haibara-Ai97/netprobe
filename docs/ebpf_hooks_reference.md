# eBPF 挂载点和上下文完整参考

## 概述

eBPF 程序的挂载点决定了程序在内核中的执行位置和可用的上下文信息。不同的挂载点提供不同的能力和限制。

## 网络相关挂载点

### XDP (eXpress Data Path)

**执行位置**: 网络驱动收到包后的最早执行点  
**性能**: 最高 (零拷贝，最少开销)  
**限制**: 无法访问 socket 信息，无法修改包内容

```c
SEC("xdp")
int xdp_program(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 可用字段:
    // ctx->data          - 包数据起始位置
    // ctx->data_end      - 包数据结束位置
    // ctx->data_meta     - 元数据区域
    // ctx->ingress_ifindex - 入站网络接口索引
    // ctx->rx_queue_index  - 接收队列索引
    
    return XDP_PASS; // XDP_DROP, XDP_ABORTED, XDP_TX, XDP_REDIRECT
}
```

**返回值含义**:
- `XDP_PASS`: 继续正常网络栈处理
- `XDP_DROP`: 丢弃数据包
- `XDP_ABORTED`: 异常终止 (通常用于错误情况)
- `XDP_TX`: 从同一接口发送包
- `XDP_REDIRECT`: 重定向到其他接口

### TC (Traffic Control)

**执行位置**: 网络栈的 qdisc 层  
**性能**: 中等  
**能力**: 可以修改包内容，可以访问更多网络栈信息

```c
SEC("tc")
int tc_program(struct __sk_buff *skb) {
    // 可用字段 (部分):
    // skb->len           - 包长度
    // skb->pkt_type      - 包类型
    // skb->mark          - SKB 标记
    // skb->queue_mapping - 队列映射
    // skb->protocol      - 协议类型
    // skb->vlan_present  - VLAN 存在标志
    // skb->vlan_tci      - VLAN TCI
    // skb->priority      - 包优先级
    // skb->ingress_ifindex - 入站接口索引
    // skb->ifindex       - 当前接口索引
    // skb->tc_index      - TC 索引
    // skb->hash          - 包哈希值
    // skb->tc_classid    - TC 分类ID
    // skb->data          - 包数据
    // skb->data_end      - 包数据结束
    // skb->family        - 协议族
    // skb->remote_ip4    - 远程IPv4地址
    // skb->local_ip4     - 本地IPv4地址
    // skb->remote_port   - 远程端口
    // skb->local_port    - 本地端口
    
    return TC_ACT_OK; // TC_ACT_SHOT, TC_ACT_REDIRECT, etc.
}
```

**返回值含义**:
- `TC_ACT_OK`: 继续处理
- `TC_ACT_SHOT`: 丢弃包
- `TC_ACT_REDIRECT`: 重定向
- `TC_ACT_PIPE`: 继续到下一个动作

### Socket 过滤器

```c
SEC("socket")
int socket_filter(struct __sk_buff *skb) {
    // 类似 TC，但在 socket 层执行
    return 0; // 0=接受, 非0=丢弃
}
```

### Socket 操作

```c
SEC("sockops")
int sock_ops(struct bpf_sock_ops *skops) {
    // 可用字段:
    // skops->op          - 操作类型
    // skops->family      - 协议族 (AF_INET, AF_INET6)
    // skops->remote_ip4  - 远程IPv4地址
    // skops->local_ip4   - 本地IPv4地址
    // skops->remote_port - 远程端口
    // skops->local_port  - 本地端口
    // skops->args[0-3]   - 操作相关参数
    
    switch (skops->op) {
        case BPF_SOCK_OPS_TIMEOUT_INIT:
            // TCP 超时初始化
            break;
        case BPF_SOCK_OPS_RWND_INIT:
            // TCP 接收窗口初始化
            break;
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
            // TCP 连接回调
            break;
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            // 主动建立连接
            break;
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            // 被动建立连接
            break;
    }
    
    return 0;
}
```

## Tracing 相关挂载点

### Kprobe/Kretprobe

**执行位置**: 内核函数入口/返回点  
**能力**: 可以访问函数参数和返回值

```c
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    // 访问函数参数:
    // 第一个参数: PT_REGS_PARM1(ctx)
    // 第二个参数: PT_REGS_PARM2(ctx)
    // 等等...
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    // 使用 bpf_core_read 安全读取内核结构
    
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int trace_tcp_connect_ret(struct pt_regs *ctx) {
    // 访问返回值:
    int ret = PT_REGS_RC(ctx);
    
    return 0;
}
```

### Tracepoint

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // ctx->args[0] = dirfd
    // ctx->args[1] = filename
    // ctx->args[2] = flags
    // ctx->args[3] = mode
    
    return 0;
}
```

### Raw Tracepoint

```c
SEC("raw_tracepoint/sched_switch")
int trace_sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    // ctx->args[0] = prev task
    // ctx->args[1] = next task
    
    return 0;
}
```

## Cgroup 相关挂载点

### Cgroup SKB

```c
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    // 在 cgroup 级别过滤入站流量
    return 1; // 1=允许, 0=拒绝
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    // 在 cgroup 级别过滤出站流量
    return 1;
}
```

### Cgroup Socket

```c
SEC("cgroup/sock")
int cgroup_sock(struct bpf_sock *sk) {
    // Socket 创建时调用
    // 可以拒绝 socket 创建
    return 1; // 1=允许, 0=拒绝
}

SEC("cgroup/bind4")
int cgroup_bind4(struct bpf_sock_addr *ctx) {
    // IPv4 bind 操作
    // ctx->user_family
    // ctx->user_ip4
    // ctx->user_port
    
    return 1;
}

SEC("cgroup/connect4")  
int cgroup_connect4(struct bpf_sock_addr *ctx) {
    // IPv4 connect 操作
    // 可以修改目标地址和端口
    
    return 1;
}
```

## Netfilter 挂载点 (需要较新内核)

```c
SEC("netfilter")
int netfilter_prog(struct bpf_nf_ctx *ctx) {
    struct sk_buff *skb = ctx->skb;
    const struct nf_hook_state *state = ctx->state;
    
    // state->hook     - Hook 点 (NF_INET_PRE_ROUTING, 等)
    // state->pf       - 协议族 (NFPROTO_IPV4, NFPROTO_IPV6)
    // state->in       - 入站网络设备
    // state->out      - 出站网络设备
    
    return NF_ACCEPT; // NF_DROP, NF_STOLEN, NF_QUEUE, NF_REPEAT
}
```

## LSM (Linux Security Module) 挂载点

```c
SEC("lsm/file_open")
int lsm_file_open(struct file *file) {
    // 文件打开安全检查
    return 0; // 0=允许, 负数=拒绝
}

SEC("lsm/task_alloc")
int lsm_task_alloc(struct task_struct *task, unsigned long clone_flags) {
    // 任务分配安全检查
    return 0;
}
```

## 检查当前系统支持的挂载点

### 使用 bpftool

```bash
# 检查支持的程序类型
bpftool feature probe | grep "eBPF program types"

# 检查支持的 Map 类型  
bpftool feature probe | grep "eBPF map types"

# 检查支持的 Helper 函数
bpftool feature probe | grep "eBPF helper functions"

# 列出当前加载的程序
bpftool prog list

# 查看特定程序的详细信息
bpftool prog show id <prog_id>
```

### 检查内核配置

```bash
# 检查内核配置
cat /boot/config-$(uname -r) | grep BPF

# 重要的配置选项:
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y  
# CONFIG_BPF_JIT=y
# CONFIG_HAVE_EBPF_JIT=y
# CONFIG_BPF_EVENTS=y
# CONFIG_NETFILTER_eBPF=y (for Netfilter eBPF)
```

### 检查内核符号

```bash
# 查看可用的内核函数 (for kprobe)
cat /proc/kallsyms | grep -E "tcp_|udp_|sk_" | head -20

# 查看可用的 tracepoint
ls /sys/kernel/debug/tracing/events/
```

## 上下文结构体内存布局

### struct xdp_md 布局

```c
struct xdp_md {
    __u32 data;          // offset 0
    __u32 data_end;      // offset 4  
    __u32 data_meta;     // offset 8
    __u32 ingress_ifindex; // offset 12
    __u32 rx_queue_index;  // offset 16
    __u32 egress_ifindex;  // offset 20 (较新内核)
};
```

### struct __sk_buff 主要字段布局

```c
struct __sk_buff {
    __u32 len;            // offset 0
    __u32 pkt_type;       // offset 4
    __u32 mark;           // offset 8
    __u32 queue_mapping;  // offset 12
    __u32 protocol;       // offset 16
    __u32 vlan_present;   // offset 20
    __u32 vlan_tci;       // offset 24
    __u32 vlan_proto;     // offset 28
    __u32 priority;       // offset 32
    __u32 ingress_ifindex; // offset 36
    __u32 ifindex;        // offset 40
    __u32 tc_index;       // offset 44
    __u32 cb[5];          // offset 48-68
    __u32 hash;           // offset 72
    __u32 tc_classid;     // offset 76
    __u32 data;           // offset 80
    __u32 data_end;       // offset 84
    // ... 更多字段
};
```

## 验证程序类型和挂载点

### 使用 libbpf 验证

```c
#include <bpf/libbpf.h>

// 检查程序类型是否支持
int check_prog_type_support(enum bpf_prog_type type) {
    return bpf_probe_prog_type(type, 0);
}

// 检查 Map 类型是否支持  
int check_map_type_support(enum bpf_map_type type) {
    return bpf_probe_map_type(type, 0);
}
```

这个完整的参考应该能帮助您了解所有主要的 eBPF 挂载点和上下文信息。建议运行我创建的检查脚本来了解您的系统具体支持哪些功能。
