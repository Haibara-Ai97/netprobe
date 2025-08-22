#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

// 包含 CO-RE 支持的 vmlinux.h (如果可用)
// #include "vmlinux.h"  // 取消注释以使用 CO-RE

// 数据结构定义
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u16 packet_size;
    __u64 timestamp;
};

// TC 设备统计键
struct tc_device_key {
    __u32 ifindex;      // 网络设备索引
    __u32 direction;    // 0=ingress, 1=egress
    __u32 stat_type;    // 统计类型 (packets/bytes)
};

// TC 详细事件信息
struct tc_event {
    __u64 timestamp;
    __u32 ifindex;
    __u32 direction;
    __u32 len;
    __u32 mark;
    __u32 priority;
    __u32 queue_mapping;
    __u32 tc_classid;
    __u8  pkt_type;
    struct flow_key flow;
};

// eBPF Maps 定义
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} packet_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64);
} flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} packet_events SEC(".maps");

// TC 设备级统计 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct tc_device_key);
    __type(value, __u64);
} tc_device_stats SEC(".maps");

// TC 事件 RingBuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} tc_events SEC(".maps");

// 每设备的流量统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64);
} tc_flow_stats SEC(".maps");

// 统计键定义
#define STAT_RX_PACKETS  0
#define STAT_TX_PACKETS  1
#define STAT_RX_BYTES    2
#define STAT_TX_BYTES    3

// TC 统计类型
#define TC_STAT_PACKETS  0
#define TC_STAT_BYTES    1

// TC 方向定义
#define TC_DIRECTION_INGRESS  0
#define TC_DIRECTION_EGRESS   1

// 辅助函数：更新统计信息
static inline void update_stats(__u32 key, __u64 value) {
    __u64 *stat = bpf_map_lookup_elem(&packet_stats, &key);
    if (stat) {
        __sync_fetch_and_add(stat, value);
    } else {
        bpf_map_update_elem(&packet_stats, &key, &value, BPF_ANY);
    }
}

// 辅助函数：更新流量统计
static inline void update_flow_stats(struct flow_key *key) {
    __u64 *count = bpf_map_lookup_elem(&flow_stats, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&flow_stats, key, &initial_count, BPF_ANY);
    }
}

// 辅助函数：发送包事件到用户空间
static inline void send_packet_event(struct packet_info *info) {
    struct packet_info *event = bpf_ringbuf_reserve(&packet_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    *event = *info;
    bpf_ringbuf_submit(event, 0);
}

// 辅助函数：更新 TC 设备统计
static inline void update_tc_device_stats(__u32 ifindex, __u32 direction, __u32 stat_type, __u64 value) {
    struct tc_device_key key = {
        .ifindex = ifindex,
        .direction = direction,
        .stat_type = stat_type
    };
    
    __u64 *stat = bpf_map_lookup_elem(&tc_device_stats, &key);
    if (stat) {
        __sync_fetch_and_add(stat, value);
    } else {
        bpf_map_update_elem(&tc_device_stats, &key, &value, BPF_ANY);
    }
}

// 辅助函数：发送 TC 事件到用户空间
static inline void send_tc_event(struct tc_event *event) {
    struct tc_event *tc_evt = bpf_ringbuf_reserve(&tc_events, sizeof(*event), 0);
    if (!tc_evt) {
        return;
    }
    
    *tc_evt = *event;
    bpf_ringbuf_submit(tc_evt, 0);
}

// 辅助函数：更新 TC 流量统计
static inline void update_tc_flow_stats(struct flow_key *key) {
    __u64 *count = bpf_map_lookup_elem(&tc_flow_stats, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&tc_flow_stats, key, &initial_count, BPF_ANY);
    }
}

// XDP 网络监控程序
SEC("xdp")
int network_monitor_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    // 检查以太网头部
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理 IP 包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 准备流量键和包信息
    struct flow_key key = {};
    struct packet_info info = {};
    
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;
    
    info.src_ip = ip->saddr;
    info.dst_ip = ip->daddr;
    info.proto = ip->protocol;
    info.packet_size = bpf_ntohs(ip->tot_len);
    info.timestamp = bpf_ktime_get_ns();
    
    // 处理 TCP 包
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
        info.src_port = bpf_ntohs(tcp->source);
        info.dst_port = bpf_ntohs(tcp->dest);
    }
    // 处理 UDP 包
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        
        key.src_port = udp->source;
        key.dst_port = udp->dest;
        info.src_port = bpf_ntohs(udp->source);
        info.dst_port = bpf_ntohs(udp->dest);
    }
    
    // 更新统计信息
    update_stats(STAT_RX_PACKETS, 1);
    update_stats(STAT_RX_BYTES, info.packet_size);
    
    // 更新流量统计
    update_flow_stats(&key);
    
    // 发送事件到用户空间
    send_packet_event(&info);
    
    return XDP_PASS;
}

// TC 出口监控程序
SEC("tc")
int network_monitor_tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    
    // 检查以太网头部
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // 只处理 IP 包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // 准备 TC 事件和流量键
    struct tc_event event = {};
    struct flow_key flow_key = {};
    
    // 填充基本信息
    event.timestamp = bpf_ktime_get_ns();
    event.ifindex = skb->ifindex;
    event.direction = TC_DIRECTION_EGRESS;
    event.len = skb->len;
    event.mark = skb->mark;
    event.priority = skb->priority;
    event.queue_mapping = skb->queue_mapping;
    event.tc_classid = skb->tc_classid;
    event.pkt_type = skb->pkt_type;
    
    // 填充流量信息
    flow_key.src_ip = ip->saddr;
    flow_key.dst_ip = ip->daddr;
    flow_key.proto = ip->protocol;
    
    event.flow.src_ip = ip->saddr;
    event.flow.dst_ip = ip->daddr;
    event.flow.proto = ip->protocol;
    
    // 处理 TCP 包
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            flow_key.src_port = tcp->source;
            flow_key.dst_port = tcp->dest;
            event.flow.src_port = tcp->source;
            event.flow.dst_port = tcp->dest;
        }
    }
    // 处理 UDP 包
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            flow_key.src_port = udp->source;
            flow_key.dst_port = udp->dest;
            event.flow.src_port = udp->source;
            event.flow.dst_port = udp->dest;
        }
    }
    
    // 更新全局统计
    update_stats(STAT_TX_PACKETS, 1);
    update_stats(STAT_TX_BYTES, bpf_ntohs(ip->tot_len));
    
    // 更新设备级 TC 统计
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_BYTES, bpf_ntohs(ip->tot_len));
    
    // 更新 TC 流量统计
    update_tc_flow_stats(&flow_key);
    
    // 发送详细事件到用户空间 (可选，用于调试或详细分析)
    // 注意：在生产环境中可能需要采样以减少开销
    if ((event.timestamp & 0xFF) == 0) {  // 1/256 采样率
        send_tc_event(&event);
    }
    
    return TC_ACT_OK;
}

// TC 入口监控程序
SEC("tc")
int network_monitor_tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    
    // 检查以太网头部
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // 只处理 IP 包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // 准备 TC 事件和流量键
    struct tc_event event = {};
    struct flow_key flow_key = {};
    
    // 填充基本信息
    event.timestamp = bpf_ktime_get_ns();
    event.ifindex = skb->ifindex;
    event.direction = TC_DIRECTION_INGRESS;
    event.len = skb->len;
    event.mark = skb->mark;
    event.priority = skb->priority;
    event.queue_mapping = skb->queue_mapping;
    event.tc_classid = skb->tc_classid;
    event.pkt_type = skb->pkt_type;
    
    // 填充流量信息
    flow_key.src_ip = ip->saddr;
    flow_key.dst_ip = ip->daddr;
    flow_key.proto = ip->protocol;
    
    event.flow.src_ip = ip->saddr;
    event.flow.dst_ip = ip->daddr;
    event.flow.proto = ip->protocol;
    
    // 处理 TCP 包
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            flow_key.src_port = tcp->source;
            flow_key.dst_port = tcp->dest;
            event.flow.src_port = tcp->source;
            event.flow.dst_port = tcp->dest;
        }
    }
    // 处理 UDP 包
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            flow_key.src_port = udp->source;
            flow_key.dst_port = udp->dest;
            event.flow.src_port = udp->source;
            event.flow.dst_port = udp->dest;
        }
    }
    
    // 更新设备级 TC 统计
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_BYTES, bpf_ntohs(ip->tot_len));
    
    // 更新 TC 流量统计
    update_tc_flow_stats(&flow_key);
    
    // 发送详细事件到用户空间 (采样)
    if ((event.timestamp & 0xFF) == 0) {  // 1/256 采样率
        send_tc_event(&event);
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
