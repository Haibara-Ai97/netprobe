//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" --target=amd64 NetworkMonitor monitor.c

// 网络监控 eBPF 程序
// 支持 XDP 和 TC hook 点的网络流量监控

// 基本类型定义
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

// BPF 程序类型
#define BPF_PROG_TYPE_XDP 6
#define BPF_PROG_TYPE_SCHED_CLS 3

// BPF Map 类型
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1

// 网络协议常量 (网络字节序)
#define ETH_P_IP_BE 0x0008  // 0x0800 in big-endian
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// XDP 返回值
#define XDP_PASS 2
#define XDP_DROP 1

// TC 返回值
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// 基本网络结构体
struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8  ihl:4,
          version:4;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 res1:4,
          doff:4,
          fin:1,
          syn:1,
          rst:1,
          psh:1,
          ack:1,
          urg:1,
          ece:1,
          cwr:1;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

struct udphdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
} __attribute__((packed));

// BPF 上下文结构体
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
};

// BPF 辅助函数声明
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
//static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
//static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
//static long (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;

// Map 定义宏
#define SEC(name) __attribute__((section(name), used))

// 字节序转换函数
static inline __u16 bpf_ntohs(__u16 netshort) {
    return (netshort >> 8) | (netshort << 8);
}

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

// eBPF Maps 定义
struct {
    __u32 type;
    __u32 max_entries;
    __u32 *key;
    __u64 *value;
} packet_stats SEC(".maps") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 10,
};

struct {
    __u32 type;
    __u32 max_entries;
    struct flow_key *key;
    __u64 *value;
} flow_stats SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 10240,
};

struct {
    __u32 type;
    __u32 max_entries;
    struct tc_device_key *key;
    __u64 *value;
} tc_device_stats SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 1024,
};

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
    void *stat_ptr = bpf_map_lookup_elem(&packet_stats, &key);
    if (stat_ptr) {
        __u64 *stat = (__u64 *)stat_ptr;
        __sync_fetch_and_add(stat, value);
    } else {
        bpf_map_update_elem(&packet_stats, &key, &value, 0);
    }
}

// 辅助函数：更新 TC 设备统计
static inline void update_tc_device_stats(__u32 ifindex, __u32 direction, __u32 stat_type, __u64 value) {
    struct tc_device_key key = {
        .ifindex = ifindex,
        .direction = direction,
        .stat_type = stat_type
    };
    
    void *stat_ptr = bpf_map_lookup_elem(&tc_device_stats, &key);
    if (stat_ptr) {
        __u64 *stat = (__u64 *)stat_ptr;
        __sync_fetch_and_add(stat, value);
    } else {
        bpf_map_update_elem(&tc_device_stats, &key, &value, 0);
    }
}

// 辅助函数：更新流量统计
static inline void update_flow_stats(struct flow_key *key) {
    void *count_ptr = bpf_map_lookup_elem(&flow_stats, key);
    if (count_ptr) {
        __u64 *count = (__u64 *)count_ptr;
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&flow_stats, key, &initial_count, 0);
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
    if (eth->h_proto != ETH_P_IP_BE) {
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
    if (eth->h_proto != ETH_P_IP_BE) {
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
    if (eth->h_proto != ETH_P_IP_BE) {
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