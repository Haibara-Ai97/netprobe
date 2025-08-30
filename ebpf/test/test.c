//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../include" --target=amd64 HookTest test.c

// eBPF 挂载点测试程序
// 用于验证不同挂载点的可用性和上下文信息

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// 测试事件结构体
struct hook_test_event {
    __u64 timestamp;        // 时间戳
    __u32 hook_type;        // 挂载点类型
    __u32 src_ip;           // 源IP (如果适用)
    __u32 dst_ip;           // 目标IP (如果适用)
    __u16 src_port;         // 源端口 (如果适用)
    __u16 dst_port;         // 目标端口 (如果适用)
    __u8  protocol;         // 协议 (如果适用)
    __u8  hook_result;      // 挂载点处理结果
    __u16 packet_len;       // 包长度 (如果适用)
    __u32 context_info[4];  // 上下文特定信息
} __attribute__((packed));

// 挂载点类型定义
#define HOOK_TYPE_XDP           1
#define HOOK_TYPE_TC            2
#define HOOK_TYPE_SOCKET        3
#define HOOK_TYPE_KPROBE        4
#define HOOK_TYPE_TRACEPOINT    5
#define HOOK_TYPE_CGROUP        6

// Ring Buffer for test events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} test_events SEC(".maps");

// 统计计数器
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 16);
} hook_stats SEC(".maps");

// Helper: 发送测试事件
static inline int send_test_event(struct hook_test_event *event) {
    struct hook_test_event *ringbuf_event;
    
    ringbuf_event = bpf_ringbuf_reserve(&test_events, sizeof(*ringbuf_event), 0);
    if (!ringbuf_event) {
        return -1;
    }
    
    *ringbuf_event = *event;
    bpf_ringbuf_submit(ringbuf_event, 0);
    
    return 0;
}

// Helper: 更新统计
static inline void update_hook_stat(__u32 hook_type) {
    __u64 *count = bpf_map_lookup_elem(&hook_stats, &hook_type);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&hook_stats, &hook_type, &initial, BPF_ANY);
    }
}

// Helper: 解析网络包信息
static inline int parse_network_packet(void *data, void *data_end, 
                                      struct hook_test_event *event) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0; // 非 IPv4 包
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return -1;
    }
    
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->protocol = ip->protocol;
    event->packet_len = bpf_ntohs(ip->tot_len);
    
    // 解析传输层端口
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            event->src_port = bpf_ntohs(tcp->source);
            event->dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            event->src_port = bpf_ntohs(udp->source);
            event->dst_port = bpf_ntohs(udp->dest);
        }
    }
    
    return 1;
}

//////////////////////////////////////////
// XDP 挂载点测试
//////////////////////////////////////////

SEC("xdp/test")
int test_xdp_hook(struct xdp_md *ctx) {
    struct hook_test_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.hook_type = HOOK_TYPE_XDP;
    event.hook_result = XDP_PASS;
    
    // 保存 XDP 上下文信息
    event.context_info[0] = ctx->ingress_ifindex;
    event.context_info[1] = ctx->rx_queue_index;
    event.context_info[2] = ctx->data_end - ctx->data; // 包大小
    
    // 解析包信息
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    parse_network_packet(data, data_end, &event);
    
    // 发送事件
    send_test_event(&event);
    update_hook_stat(HOOK_TYPE_XDP);
    
    return XDP_PASS;
}

//////////////////////////////////////////  
// TC 挂载点测试
//////////////////////////////////////////

SEC("tc/test")
int test_tc_hook(struct __sk_buff *skb) {
    struct hook_test_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.hook_type = HOOK_TYPE_TC;
    event.hook_result = TC_ACT_OK;
    
    // 保存 TC 上下文信息
    event.context_info[0] = skb->ifindex;
    event.context_info[1] = skb->ingress_ifindex;
    event.context_info[2] = skb->protocol;
    event.context_info[3] = skb->mark;
    
    // SKB 中已有的网络信息
    event.src_ip = skb->remote_ip4;
    event.dst_ip = skb->local_ip4;
    event.src_port = skb->remote_port;
    event.dst_port = skb->local_port;
    event.packet_len = skb->len;
    
    // 发送事件
    send_test_event(&event);
    update_hook_stat(HOOK_TYPE_TC);
    
    return TC_ACT_OK;
}

//////////////////////////////////////////
// Socket 挂载点测试  
//////////////////////////////////////////

SEC("socket/test")
int test_socket_hook(struct __sk_buff *skb) {
    struct hook_test_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.hook_type = HOOK_TYPE_SOCKET;
    event.hook_result = 0; // 接受包
    
    // Socket 层信息
    event.src_ip = skb->remote_ip4;
    event.dst_ip = skb->local_ip4;
    event.src_port = skb->remote_port;
    event.dst_port = skb->local_port;
    event.packet_len = skb->len;
    event.protocol = skb->protocol;
    
    // 保存 Socket 特定信息
    event.context_info[0] = skb->family;
    event.context_info[1] = skb->type;
    event.context_info[2] = skb->protocol;
    
    send_test_event(&event);
    update_hook_stat(HOOK_TYPE_SOCKET);
    
    return 0;
}

//////////////////////////////////////////
// Kprobe 挂载点测试
//////////////////////////////////////////

SEC("kprobe/tcp_v4_connect")
int test_kprobe_hook(struct pt_regs *ctx) {
    struct hook_test_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.hook_type = HOOK_TYPE_KPROBE;
    event.hook_result = 0;
    
    // 获取函数参数 (第一个参数是 struct sock *)
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    // 保存 kprobe 特定信息
    event.context_info[0] = (__u32)(__u64)sk; // socket 指针 (低32位)
    event.context_info[1] = bpf_get_current_pid_tgid() >> 32; // PID
    event.context_info[2] = bpf_get_current_pid_tgid() & 0xFFFFFFFF; // TID
    
    send_test_event(&event);
    update_hook_stat(HOOK_TYPE_KPROBE);
    
    return 0;
}

//////////////////////////////////////////
// Tracepoint 挂载点测试
//////////////////////////////////////////

SEC("tracepoint/syscalls/sys_enter_socket")
int test_tracepoint_hook(void *ctx) {
    struct hook_test_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.hook_type = HOOK_TYPE_TRACEPOINT;
    event.hook_result = 0;
    
    // Tracepoint 特定信息
    event.context_info[0] = bpf_get_current_pid_tgid() >> 32; // PID
    event.context_info[1] = bpf_get_current_uid_gid() & 0xFFFFFFFF; // UID
    
    send_test_event(&event);
    update_hook_stat(HOOK_TYPE_TRACEPOINT);
    
    return 0;
}

//////////////////////////////////////////
// Cgroup 挂载点测试
//////////////////////////////////////////

SEC("cgroup_skb/ingress")
int test_cgroup_ingress(struct __sk_buff *skb) {
    struct hook_test_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.hook_type = HOOK_TYPE_CGROUP;
    event.hook_result = 1; // 允许
    
    // Cgroup SKB 信息
    event.src_ip = skb->remote_ip4;
    event.dst_ip = skb->local_ip4;
    event.src_port = skb->remote_port;
    event.dst_port = skb->local_port;
    event.packet_len = skb->len;
    
    // Cgroup 特定信息
    event.context_info[0] = skb->ifindex;
    event.context_info[1] = 0; // ingress 标记
    
    send_test_event(&event);
    update_hook_stat(HOOK_TYPE_CGROUP);
    
    return 1;
}

SEC("cgroup_skb/egress")
int test_cgroup_egress(struct __sk_buff *skb) {
    struct hook_test_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.hook_type = HOOK_TYPE_CGROUP;
    event.hook_result = 1; // 允许
    
    // Cgroup SKB 信息
    event.src_ip = skb->local_ip4;
    event.dst_ip = skb->remote_ip4;
    event.src_port = skb->local_port;
    event.dst_port = skb->remote_port;
    event.packet_len = skb->len;
    
    // Cgroup 特定信息  
    event.context_info[0] = skb->ifindex;
    event.context_info[1] = 1; // egress 标记
    
    send_test_event(&event);
    update_hook_stat(HOOK_TYPE_CGROUP);
    
    return 1;
}

//////////////////////////////////////////
// 辅助测试函数
//////////////////////////////////////////

// 测试 Map 访问
SEC("xdp/map_test")
int test_map_access(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&hook_stats, &key);
    
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&hook_stats, &key, &initial, BPF_ANY);
    }
    
    return XDP_PASS;
}

// 测试 Helper 函数可用性
SEC("xdp/helper_test")  
int test_helpers(struct xdp_md *ctx) {
    // 测试时间函数
    __u64 time1 = bpf_ktime_get_ns();
    __u64 time2 = bpf_ktime_get_boot_ns();
    
    // 测试随机数函数
    __u32 random = bpf_get_prandom_u32();
    
    // 测试进程信息函数
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    // 构造测试事件
    struct hook_test_event event = {0};
    event.timestamp = time1;
    event.hook_type = HOOK_TYPE_XDP;
    event.context_info[0] = (__u32)time2;
    event.context_info[1] = random;
    event.context_info[2] = (__u32)(pid_tgid >> 32);
    event.context_info[3] = (__u32)(uid_gid & 0xFFFFFFFF);
    
    send_test_event(&event);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
