//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../include" --target=amd64 NetworkMonitor monitor.c

// 网络监控 eBPF 程序
// 支持 XDP 和 TC hook 点的网络流量监控

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

// 自定义数据结构
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

// TC 设备统计键
struct tc_device_key {
    __u32 ifindex;      // 网络设备索引
    __u32 direction;    // 0=ingress, 1=egress
    __u32 stat_type;    // 统计类型 (packets/bytes)
};

// eBPF Maps 定义
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10);
} packet_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tc_device_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} tc_device_stats SEC(".maps");

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

// 辅助函数：安全的统计更新
static inline void update_stats(__u32 key, __u64 value) {
    __u64 *stat_ptr = bpf_map_lookup_elem(&packet_stats, &key);
    if (stat_ptr) {
        __sync_fetch_and_add(stat_ptr, value);
    } else {
        bpf_map_update_elem(&packet_stats, &key, &value, BPF_ANY);
    }
}

// 辅助函数：更新 TC 设备统计
static inline void update_tc_device_stats(__u32 ifindex, __u32 direction, __u32 stat_type, __u64 value) {
    struct tc_device_key key = {
        .ifindex = ifindex,
        .direction = direction,
        .stat_type = stat_type
    };
    
    __u64 *stat_ptr = bpf_map_lookup_elem(&tc_device_stats, &key);
    if (stat_ptr) {
        __sync_fetch_and_add(stat_ptr, value);
    } else {
        bpf_map_update_elem(&tc_device_stats, &key, &value, BPF_ANY);
    }
}

// 辅助函数：更新流量统计
static inline void update_flow_stats(struct flow_key *key) {
    __u64 *count_ptr = bpf_map_lookup_elem(&flow_stats, key);
    if (count_ptr) {
        __sync_fetch_and_add(count_ptr, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&flow_stats, key, &initial_count, BPF_ANY);
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
    
    // 检查是否为 IP 包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 准备流量键
    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;
    
    // 处理 TCP/UDP 端口
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            key.src_port = udp->source;
            key.dst_port = udp->dest;
        }
    }
    
    // 获取包长度
    __u16 packet_len = bpf_ntohs(ip->tot_len);
    
    // 更新统计信息
    update_stats(STAT_RX_PACKETS, 1);
    update_stats(STAT_RX_BYTES, packet_len);
    
    // 更新流量统计
    update_flow_stats(&key);
    
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
    
    // 检查是否为 IP 包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // 准备流量键
    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;
    
    // 处理 TCP/UDP 端口
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            key.src_port = udp->source;
            key.dst_port = udp->dest;
        }
    }
    
    // 获取包长度
    __u16 packet_len = bpf_ntohs(ip->tot_len);
    
    // 更新全局统计
    update_stats(STAT_TX_PACKETS, 1);
    update_stats(STAT_TX_BYTES, packet_len);
    
    // 更新设备级 TC 统计
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_BYTES, packet_len);
    
    // 更新流量统计
    update_flow_stats(&key);
    
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
    
    // 检查是否为 IP 包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // 准备流量键
    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;
    
    // 处理 TCP/UDP 端口
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            key.src_port = udp->source;
            key.dst_port = udp->dest;
        }
    }
    
    // 获取包长度
    __u16 packet_len = bpf_ntohs(ip->tot_len);
    
    // 更新设备级 TC 统计
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_BYTES, packet_len);
    
    // 更新流量统计
    update_flow_stats(&key);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
