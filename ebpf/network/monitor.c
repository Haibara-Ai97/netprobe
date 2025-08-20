#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

// 统计键定义
#define STAT_RX_PACKETS  0
#define STAT_TX_PACKETS  1
#define STAT_RX_BYTES    2
#define STAT_TX_BYTES    3

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
    
    // 更新发送统计
    update_stats(STAT_TX_PACKETS, 1);
    update_stats(STAT_TX_BYTES, bpf_ntohs(ip->tot_len));
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
