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
    __u8  hook_point;   // Hook point: 1=XDP, 2=TC_INGRESS, 3=TC_EGRESS, 4=NETFILTER, 5=SOCKET
    __u8  pad[3];       // Padding for alignment
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
// 全局流量统计map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 16); // Expanded for additional statistics
} packet_stats SEC(".maps");

// Hash map for per-flow statistics tracking
// 流级别流量统计
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

// Rate limiting map for DDoS protection
// Key: source IP, Value: last seen timestamp
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 65536);
} rate_limit_map SEC(".maps");

// Load balancer statistics
// Key: target interface, Value: packet count
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 16);
} lb_stats SEC(".maps");

// Blacklist map for security filtering
// Key: IP address, Value: block timestamp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} blacklist_map SEC(".maps");

// 统计键定义
#define STAT_RX_PACKETS     0
#define STAT_TX_PACKETS     1
#define STAT_RX_BYTES       2
#define STAT_TX_BYTES       3
#define STAT_EVENTS_SENT    4
#define STAT_EVENTS_DROPPED 5
#define STAT_BUFFER_FULL    6
#define STAT_PARSE_ERRORS   7
#define STAT_XDP_DROP       8
#define STAT_XDP_PASS       9
#define STAT_XDP_REDIRECT   10
#define STAT_DDOS_BLOCKED   11
#define STAT_LB_DECISIONS   12
#define STAT_SECURITY_EVENTS 13

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
#define EVENT_TYPE_DDOS      3
#define EVENT_TYPE_LOAD_BALANCE 4

// Hook 位置定义
#define HOOK_XDP           1
#define HOOK_TC_INGRESS    2  
#define HOOK_TC_EGRESS     3
#define HOOK_NETFILTER     4  // 为将来的Netfilter hook预留
#define HOOK_SOCKET        5  // 为将来的Socket hook预留

// DDoS 检测阈值
#define DDOS_RATE_LIMIT_NS   1000000    // 1ms between packets
#define DDOS_PACKET_THRESHOLD 1000      // Max packets per time window
#define BLACKLIST_DURATION_NS 60000000000ULL // 60 seconds

// 前向声明
static inline void update_stats(__u32 key, __u64 value);
static inline void update_flow_stats(struct flow_key *key);
static inline void update_tc_device_stats(__u32 ifindex, __u32 direction, __u32 stat_type, __u64 value);
static inline int check_rate_limit(__u32 src_ip);
static inline int check_blacklist(__u32 src_ip);
static inline void add_to_blacklist(__u32 src_ip);

// Ring Buffer 配置映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ringbuf_config SEC(".maps");

#define CONFIG_ENABLE_XDP_EVENTS     (1 << 0)
#define CONFIG_ENABLE_TC_EVENTS      (1 << 1)
#define CONFIG_ENABLE_DETAILED_EVENTS (1 << 2)

// Helper function: Check if should send ring buffer event
static inline int should_send_event(__u8 hook_type) {
    __u32 key = 0;
    __u32 *config = bpf_map_lookup_elem(&ringbuf_config, &key);
    if (!config) {
        // Default: only TC ingress sends events to avoid duplicates
        return (hook_type == HOOK_TC_INGRESS);
    }
    
    switch (hook_type) {
        case HOOK_XDP:
            return (*config & CONFIG_ENABLE_XDP_EVENTS) != 0;
        case HOOK_TC_INGRESS:
        case HOOK_TC_EGRESS:
            return (*config & CONFIG_ENABLE_TC_EVENTS) != 0;
        default:
            return 0;
    }
}

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

// Packet parsing context
struct parse_context {
    __u32 ifindex;
    __u8 direction;
    __u8 hook_point;
};

// Helper function: Parse packet headers into event structure
static inline int parse_packet_to_event(void *data, void *data_end, 
                                       struct network_event *event, 
                                       struct parse_context *ctx) {
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
    event->direction = ctx->direction;
    event->event_type = EVENT_TYPE_NORMAL;
    event->hook_point = ctx->hook_point;  // 添加hook点信息
    event->ifindex = ctx->ifindex;
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

// Helper function: Check rate limiting for DDoS protection
static inline int check_rate_limit(__u32 src_ip) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    
    if (last_seen) {
        if (now - *last_seen < DDOS_RATE_LIMIT_NS) {
            // Rate limit exceeded
            return 1;
        }
    }
    
    // Update timestamp
    bpf_map_update_elem(&rate_limit_map, &src_ip, &now, BPF_ANY);
    return 0;
}

// Helper function: Check if IP is blacklisted
static inline int check_blacklist(__u32 src_ip) {
    __u64 *blocked_time = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (!blocked_time) {
        return 0; // Not blacklisted
    }
    
    __u64 now = bpf_ktime_get_ns();
    if (now - *blocked_time > BLACKLIST_DURATION_NS) {
        // Blacklist expired, remove entry
        bpf_map_delete_elem(&blacklist_map, &src_ip);
        return 0;
    }
    
    return 1; // Still blacklisted
}

// Helper function: Add IP to blacklist
static inline void add_to_blacklist(__u32 src_ip) {
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&blacklist_map, &src_ip, &now, BPF_ANY);
    update_stats(STAT_DDOS_BLOCKED, 1);
}

// Helper function: Update load balancer statistics
static inline void update_lb_stats(__u32 target_if) {
    __u64 *count_ptr = bpf_map_lookup_elem(&lb_stats, &target_if);
    if (count_ptr) {
        __sync_fetch_and_add(count_ptr, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&lb_stats, &target_if, &initial_count, BPF_ANY);
    }
    update_stats(STAT_LB_DECISIONS, 1);
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
    struct parse_context parse_ctx = {
        .ifindex = ctx->ingress_ifindex,
        .direction = TC_DIRECTION_INGRESS,
        .hook_point = HOOK_XDP
    };
    if (parse_packet_to_event(data, data_end, &event, &parse_ctx) < 0) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return XDP_PASS;
    }
    
    // Only send event if configured (避免重复)
    if (should_send_event(HOOK_XDP)) {
        send_network_event(&event);
    }
    
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

// Advanced XDP Filter with DDoS Protection
// High-performance packet filtering and attack detection
SEC("xdp/advanced_filter")
int xdp_advanced_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    // Validate Ethernet header
    if ((void *)(eth + 1) > data_end) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return XDP_ABORTED;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return XDP_ABORTED;
    }
    
    __u32 src_ip = ip->saddr;
    
    // Check blacklist first
    if (check_blacklist(src_ip)) {
        update_stats(STAT_XDP_DROP, 1);
        return XDP_DROP;
    }
    
    // Check rate limiting for DDoS protection
    if (check_rate_limit(src_ip)) {
        // Add to blacklist after repeated violations
        add_to_blacklist(src_ip);
        update_stats(STAT_XDP_DROP, 1);
        return XDP_DROP;
    }
    
    // Parse packet and create event
    struct network_event event = {0};
    struct parse_context parse_ctx = {
        .ifindex = ctx->ingress_ifindex,
        .direction = TC_DIRECTION_INGRESS,
        .hook_point = HOOK_XDP
    };
    if (parse_packet_to_event(data, data_end, &event, &parse_ctx) < 0) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return XDP_PASS;
    }
    
    // Check for suspicious patterns
    if (event.packet_len < 64) {
        // Potential attack packet (too small)
        event.event_type = EVENT_TYPE_SECURITY;
        send_network_event(&event);
        update_stats(STAT_SECURITY_EVENTS, 1);
        add_to_blacklist(src_ip);
        update_stats(STAT_XDP_DROP, 1);
        return XDP_DROP;
    }
    
    // Protocol-specific filtering
    if (event.protocol == IPPROTO_ICMP) {
        // Limit ICMP rate to prevent ping floods
        __u32 icmp_key = STAT_SECURITY_EVENTS + 1; // Use unused stat key
        __u64 *icmp_count = bpf_map_lookup_elem(&packet_stats, &icmp_key);
        if (icmp_count && *icmp_count > 100) { // Max 100 ICMP per time window
            event.event_type = EVENT_TYPE_DDOS;
            send_network_event(&event);
            update_stats(STAT_XDP_DROP, 1);
            return XDP_DROP;
        }
        update_stats(icmp_key, 1);
    }
    
    // Send event for monitoring
    if (should_send_event(HOOK_XDP)) {
        send_network_event(&event);
    }
    
    // Update statistics
    update_stats(STAT_RX_PACKETS, 1);
    update_stats(STAT_RX_BYTES, event.packet_len);
    update_stats(STAT_XDP_PASS, 1);
    
    return XDP_PASS;
}

// XDP Load Balancer Program
// Distributes packets across multiple interfaces or queues
SEC("xdp/load_balancer")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    // Validate Ethernet header
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Only balance IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Simple hash-based load balancing
    __u32 hash = 0;
    hash ^= ip->saddr;
    hash ^= ip->daddr;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            hash ^= tcp->source;
            hash ^= tcp->dest;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            hash ^= udp->source;
            hash ^= udp->dest;
        }
    }
    
    // Calculate target interface (assuming 4 interfaces for load balancing)
    __u32 target_if = hash % 4;
    
    // Update load balancer statistics
    update_lb_stats(target_if);
    
    // Log load balancing decision
    struct network_event event = {0};
    struct parse_context parse_ctx = {
        .ifindex = ctx->ingress_ifindex,
        .direction = TC_DIRECTION_INGRESS,
        .hook_point = HOOK_TC_INGRESS
    };
    if (parse_packet_to_event(data, data_end, &event, &parse_ctx) >= 0) {
        event.event_type = EVENT_TYPE_LOAD_BALANCE;
        // Store target interface in ifindex field for debugging
        event.ifindex = target_if;
        send_network_event(&event);
    }
    
    // For demonstration, we'll just pass the packet
    // In real implementation, you would use bpf_redirect() to target interface
    // return bpf_redirect(target_if, 0);
    
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
    struct parse_context parse_ctx = {
        .ifindex = skb->ifindex,
        .direction = TC_DIRECTION_EGRESS,
        .hook_point = HOOK_TC_EGRESS
    };
    if (parse_packet_to_event(data, data_end, &event, &parse_ctx) < 0) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return TC_ACT_OK;
    }
    
    // Only send event if configured (避免重复)
    if (should_send_event(HOOK_TC_EGRESS)) {
        send_network_event(&event);
    }
    
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
    struct parse_context parse_ctx = {
        .ifindex = skb->ifindex,
        .direction = TC_DIRECTION_INGRESS,
        .hook_point = HOOK_TC_INGRESS
    };
    if (parse_packet_to_event(data, data_end, &event, &parse_ctx) < 0) {
        update_stats(STAT_PARSE_ERRORS, 1);
        return TC_ACT_OK;
    }
    
    if (should_send_event(HOOK_TC_INGRESS)) {
        send_network_event(&event);
    }
    
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
