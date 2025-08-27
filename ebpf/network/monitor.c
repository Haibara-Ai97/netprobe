//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../include" --target=amd64 NetworkMonitor monitor.c

// NetProbe eBPF Network Monitor with Ring Buffer
// High-performance network traffic monitoring using zero-copy Ring Buffer technology
// Provides real-time event streaming and per-interface packet statistics

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

// Network event structure for Ring Buffer zero-copy transmission
struct network_event {
    __u64 timestamp;    // Event timestamp in nanoseconds
    __u32 src_ip;       // Source IP address
    __u32 dst_ip;       // Destination IP address
    __u16 src_port;     // Source port
    __u16 dst_port;     // Destination port
    __u16 packet_len;   // Packet length in bytes
    __u8  protocol;     // IP protocol (TCP/UDP/ICMP/etc)
    __u8  direction;    // Traffic direction: 0=ingress, 1=egress
    __u8  tcp_flags;    // TCP flags (if TCP packet)
    __u8  event_type;   // Event type: 0=normal, 1=anomaly, 2=security
    __u32 ifindex;      // Network interface index
} __attribute__((packed));

// eBPF Maps for data collection and statistics storage

// Zero-copy Ring Buffer for real-time event streaming
// This is the primary data transmission mechanism for high-performance monitoring
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB ring buffer for zero-copy events
} events SEC(".maps");

// Simple packet counter array map for basic statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 16); // Expanded for additional statistics
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
#define STAT_RX_PACKETS     0
#define STAT_TX_PACKETS     1
#define STAT_RX_BYTES       2
#define STAT_TX_BYTES       3
#define STAT_EVENTS_SENT    4
#define STAT_EVENTS_DROPPED 5
#define STAT_BUFFER_FULL    6
#define STAT_PARSE_ERRORS   7

// TC 统计类型
#define TC_STAT_PACKETS  0
#define TC_STAT_BYTES    1

// TC 方向定义
#define TC_DIRECTION_INGRESS  0
#define TC_DIRECTION_EGRESS   1

// 事件类型定义
#define EVENT_TYPE_NORMAL    0
#define EVENT_TYPE_ANOMALY   1
#define EVENT_TYPE_SECURITY  2

// 前向声明
static inline void update_stats(__u32 key, __u64 value);
static inline void update_flow_stats(struct flow_key *key);
static inline void update_tc_device_stats(__u32 ifindex, __u32 direction, __u32 stat_type, __u64 value);

// Helper function: Send network event via Ring Buffer (zero-copy)
static inline int send_network_event(struct network_event *event) {
    struct network_event *ringbuf_event;
    
    // Reserve space in ring buffer
    ringbuf_event = bpf_ringbuf_reserve(&events, sizeof(*ringbuf_event), 0);
    if (!ringbuf_event) {
        // Buffer full, update drop statistics
        update_stats(STAT_EVENTS_DROPPED, 1);
        update_stats(STAT_BUFFER_FULL, 1);
        return -1;
    }
    
    // Copy event data to ring buffer (minimal copy)
    *ringbuf_event = *event;
    
    // Submit event to user space (zero-copy from this point)
    bpf_ringbuf_submit(ringbuf_event, 0);
    update_stats(STAT_EVENTS_SENT, 1);
    
    return 0;
}

// Helper function: Parse packet headers into event structure
static inline int parse_packet_to_event(void *data, void *data_end, 
                                       struct network_event *event, __u32 ifindex, __u8 direction) {
    struct ethhdr *eth = data;
    
    // Validate Ethernet header
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return -1;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return -1;
    }
    
    // Fill basic event information
    event->timestamp = bpf_ktime_get_ns();
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->protocol = ip->protocol;
    event->packet_len = bpf_ntohs(ip->tot_len);
    event->direction = direction;
    event->event_type = EVENT_TYPE_NORMAL;
    event->ifindex = ifindex;
    event->tcp_flags = 0;
    event->src_port = 0;
    event->dst_port = 0;
    
    // Parse transport layer headers
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            event->src_port = bpf_ntohs(tcp->source);
            event->dst_port = bpf_ntohs(tcp->dest);
            event->tcp_flags = ((__u8 *)tcp)[13]; // TCP flags byte
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            event->src_port = bpf_ntohs(udp->source);
            event->dst_port = bpf_ntohs(udp->dest);
        }
    }
    
    return 0;
}

// 辅助函数：安全的统计更新
static inline void update_stats(__u32 key, __u64 value) {
    __u64 *stat_ptr = bpf_map_lookup_elem(&packet_stats, &key);
    if (stat_ptr) {
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

// XDP Network Monitor Program with Ring Buffer Support
// Attached to network interface for high-performance packet processing
// Processes packets at the earliest point in the network stack
SEC("xdp")
int network_monitor_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse packet and create event
    struct network_event event = {0};
    if (parse_packet_to_event(data, data_end, &event, ctx->ingress_ifindex, TC_DIRECTION_INGRESS) < 0) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return XDP_PASS;
    }
    
    // Send event via ring buffer
    send_network_event(&event);
    
    // Prepare flow key for legacy statistics
    struct flow_key flow_key = {
        .src_ip = event.src_ip,
        .dst_ip = event.dst_ip,
        .src_port = bpf_htons(event.src_port),
        .dst_port = bpf_htons(event.dst_port),
        .proto = event.protocol,
    };
    
    // Update traditional statistics
    update_stats(STAT_RX_PACKETS, 1);
    update_stats(STAT_RX_BYTES, event.packet_len);
    update_flow_stats(&flow_key);
    
    return XDP_PASS;
}

// TC Egress Monitor Program with Ring Buffer Support  
// Monitors outbound traffic at the Traffic Control layer
// Provides egress packet and byte counting per interface
SEC("tc")
int network_monitor_tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse packet and create event
    struct network_event event = {0};
    if (parse_packet_to_event(data, data_end, &event, skb->ifindex, TC_DIRECTION_EGRESS) < 0) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return TC_ACT_OK;
    }
    
    // Send event via ring buffer
    send_network_event(&event);
    
    // Prepare flow key for legacy statistics
    struct flow_key flow_key = {
        .src_ip = event.src_ip,
        .dst_ip = event.dst_ip,
        .src_port = bpf_htons(event.src_port),
        .dst_port = bpf_htons(event.dst_port),
        .proto = event.protocol,
    };
    
    // Update traditional statistics
    update_stats(STAT_TX_PACKETS, 1);
    update_stats(STAT_TX_BYTES, event.packet_len);
    
    // Update per-interface TC layer statistics for egress traffic
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_EGRESS, TC_STAT_BYTES, event.packet_len);
    
    // Update flow-level statistics for traffic analysis
    update_flow_stats(&flow_key);
    
    return TC_ACT_OK;
}

// TC Ingress Monitor Program with Ring Buffer Support
// Monitors inbound traffic at the Traffic Control layer  
// Provides ingress packet and byte counting per interface
SEC("tc")
int network_monitor_tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse packet and create event
    struct network_event event = {0};
    if (parse_packet_to_event(data, data_end, &event, skb->ifindex, TC_DIRECTION_INGRESS) < 0) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return TC_ACT_OK;
    }
    
    // Send event via ring buffer
    send_network_event(&event);
    
    // Prepare flow key for legacy statistics
    struct flow_key flow_key = {
        .src_ip = event.src_ip,
        .dst_ip = event.dst_ip,
        .src_port = bpf_htons(event.src_port),
        .dst_port = bpf_htons(event.dst_port),
        .proto = event.protocol,
    };
    
    // Update per-interface TC layer statistics for ingress traffic
    // This is the primary data collection point for network monitoring
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_PACKETS, 1);
    update_tc_device_stats(skb->ifindex, TC_DIRECTION_INGRESS, TC_STAT_BYTES, event.packet_len);
    
    // Update flow-level statistics for detailed traffic analysis
    update_flow_stats(&flow_key);
    
    return TC_ACT_OK;
}

// Required license declaration for eBPF programs
char _license[] SEC("license") = "GPL";
