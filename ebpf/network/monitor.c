//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../include" --target=amd64 NetworkMonitor monitor.c

// NetProbe eBPF Network Monitor
// High-performance network traffic monitoring using TC (Traffic Control) hook points
// Provides per-interface packet and byte statistics for ingress/egress traffic

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

// Flow identification key for network traffic tracking
struct flow_key {
    __u32 src_ip;       // Source IP address
    __u32 dst_ip;       // Destination IP address  
    __u16 src_port;     // Source port
    __u16 dst_port;     // Destination port
    __u8  proto;        // Protocol (TCP/UDP/etc)
    __u8  pad[3];       // Padding for alignment
};

// TC device statistics key for per-interface monitoring
struct tc_device_key {
    __u32 ifindex;      // Network interface index
    __u32 direction;    // Traffic direction: 0=ingress, 1=egress
    __u32 stat_type;    // Statistics type: 0=packets, 1=bytes
};

// eBPF Maps for data collection and statistics storage

// Simple packet counter array map for basic statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10);
} packet_stats SEC(".maps");

// Hash map for per-flow statistics tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} flow_stats SEC(".maps");

// Hash map for per-interface TC layer statistics
// Key: tc_device_key, Value: counter (packets or bytes)
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

// Helper function: Update packet statistics with atomic operations
static inline void update_packet_stats(__u32 key, __u64 value) {
    __u64 *stat_ptr = bpf_map_lookup_elem(&packet_stats, &key);
    if (stat_ptr) {
        // Use atomic add to prevent race conditions in multi-CPU environments
        __sync_fetch_and_add(stat_ptr, value);
    } else {
        bpf_map_update_elem(&packet_stats, &key, &value, BPF_ANY);
    }
}

// Helper function: Update TC device statistics for interface monitoring
static inline void update_tc_device_stats(__u32 ifindex, __u32 direction, __u32 stat_type, __u64 value) {
    struct tc_device_key key = {
        .ifindex = ifindex,
        .direction = direction,
        .stat_type = stat_type
    };
    
    __u64 *stat_ptr = bpf_map_lookup_elem(&tc_device_stats, &key);
    if (stat_ptr) {
        // Atomic increment for thread-safe statistics update
        __sync_fetch_and_add(stat_ptr, value);
    } else {
        bpf_map_update_elem(&tc_device_stats, &key, &value, BPF_ANY);
    }
}

// Helper function: Update flow-based statistics for network flow tracking
static inline void update_flow_stats(struct flow_key *key) {
    __u64 *count_ptr = bpf_map_lookup_elem(&flow_stats, key);
    if (count_ptr) {
        __sync_fetch_and_add(count_ptr, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&flow_stats, key, &initial_count, BPF_ANY);
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

// XDP Network Monitor Program
// Attached to network interface for high-performance packet processing
// Processes packets at the earliest point in the network stack
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
    
    // Extract packet length from IP header
    __u16 packet_len = bpf_ntohs(ip->tot_len);
    
    // Update packet and byte statistics
    update_stats(STAT_RX_PACKETS, 1);
    update_stats(STAT_RX_BYTES, packet_len);
    
    // Update per-flow statistics for traffic analysis
    update_flow_stats(&key);
    
    return XDP_PASS;
}

// TC Egress Monitor Program  
// Monitors outbound traffic at the Traffic Control layer
// Provides egress packet and byte counting per interface
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
    
    // Extract packet length from IP header
    __u16 packet_len = bpf_ntohs(ip->tot_len);
    
    // Update global transmit statistics
    update_stats(STAT_TX_PACKETS, 1);
    update_stats(STAT_TX_BYTES, packet_len);
    
    // Update per-interface TC layer statistics for egress traffic
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_BYTES, packet_len);
    
    // Update flow-level statistics for traffic analysis
    update_flow_stats(&key);
    
    return TC_ACT_OK;
}

// TC Ingress Monitor Program
// Monitors inbound traffic at the Traffic Control layer  
// Provides ingress packet and byte counting per interface
SEC("tc")
int network_monitor_tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    
    // Validate Ethernet header bounds
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // Only process IPv4 packets
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
    
    // Extract packet length from IP header for byte counting
    __u16 packet_len = bpf_ntohs(ip->tot_len);
    
    // Update per-interface TC layer statistics for ingress traffic
    // This is the primary data collection point for network monitoring
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_BYTES, packet_len);
    
    // Update flow-level statistics for detailed traffic analysis
    update_flow_stats(&key);
    
    return TC_ACT_OK;
}

// Required license declaration for eBPF programs
char _license[] SEC("license") = "GPL";
