// +build ignore

// NetProbe eBPF Netfilter Monitor  
// Netfilter 层网络包过滤和防火墙监控
// 提供包过滤、NAT跟踪、连接跟踪等功能

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Netfilter 常量定义（模拟）
#define NF_INET_PRE_ROUTING     0
#define NF_INET_LOCAL_IN        1
#define NF_INET_FORWARD         2
#define NF_INET_LOCAL_OUT       3
#define NF_INET_POST_ROUTING    4

#define NF_DROP                 0
#define NF_ACCEPT               1
#define NF_STOLEN               2
#define NF_QUEUE                3
#define NF_REPEAT               4
#define NF_STOP                 5

// Netfilter 事件类型
#define NF_EVENT_PREROUTING     0
#define NF_EVENT_LOCAL_IN       1
#define NF_EVENT_FORWARD        2
#define NF_EVENT_LOCAL_OUT      3
#define NF_EVENT_POSTROUTING    4
#define NF_EVENT_DROP           5
#define NF_EVENT_NAT            6
#define NF_EVENT_CONNTRACK      7

// 包决策类型
#define NF_VERDICT_ACCEPT       0
#define NF_VERDICT_DROP         1
#define NF_VERDICT_QUEUE        2
#define NF_VERDICT_STOLEN       3

// Netfilter 规则类型
#define NF_RULE_ALLOW           0
#define NF_RULE_DENY            1
#define NF_RULE_NAT             2
#define NF_RULE_REDIRECT        3

// 连接跟踪状态
#define CT_STATE_NEW            0
#define CT_STATE_ESTABLISHED    1
#define CT_STATE_RELATED        2
#define CT_STATE_INVALID        3

// Netfilter 包信息结构体
struct nf_packet_info {
    __u32 src_ip;           // 源IP地址
    __u32 dst_ip;           // 目标IP地址
    __u16 src_port;         // 源端口
    __u16 dst_port;         // 目标端口
    __u8  protocol;         // 协议类型
    __u8  tos;              // 服务类型
    __u16 packet_len;       // 包长度
    __u32 mark;             // Netfilter 标记
    __u32 hook;             // Hook 点
    __u8  verdict;          // 决策结果
    __u8  rule_id;          // 规则ID
    __u16 frag_off;         // 分片偏移
};

// Netfilter 事件结构体 - Ring Buffer 传输
struct netfilter_event {
    __u64 timestamp;        // 事件时间戳
    __u32 event_type;       // 事件类型
    __u32 src_ip;           // 源IP
    __u32 dst_ip;           // 目标IP
    __u16 src_port;         // 源端口
    __u16 dst_port;         // 目标端口
    __u8  protocol;         // 协议
    __u8  verdict;          // 包决策
    __u8  hook_point;       // Hook 点
    __u8  rule_action;      // 规则动作
    __u32 packet_len;       // 包长度
    __u32 mark;             // Netfilter 标记
    __u32 conn_state;       // 连接状态
    __u32 nat_src_ip;       // NAT 前源IP
    __u32 nat_dst_ip;       // NAT 前目标IP
    __u16 nat_src_port;     // NAT 前源端口
    __u16 nat_dst_port;     // NAT 前目标端口
};

// 防火墙规则结构体
struct firewall_rule {
    __u32 rule_id;          // 规则ID
    __u32 src_ip;           // 源IP（0表示任意）
    __u32 dst_ip;           // 目标IP（0表示任意）
    __u32 src_mask;         // 源IP掩码
    __u32 dst_mask;         // 目标IP掩码
    __u16 src_port_min;     // 源端口范围开始
    __u16 src_port_max;     // 源端口范围结束
    __u16 dst_port_min;     // 目标端口范围开始
    __u16 dst_port_max;     // 目标端口范围结束
    __u8  protocol;         // 协议（0表示任意）
    __u8  action;           // 动作
    __u8  direction;        // 方向：0=in, 1=out, 2=both
    __u8  enabled;          // 是否启用
    __u64 hit_count;        // 命中次数
    __u64 byte_count;       // 字节计数
};

// 连接跟踪条目
struct connection_track {
    __u32 src_ip;           // 源IP
    __u32 dst_ip;           // 目标IP
    __u16 src_port;         // 源端口
    __u16 dst_port;         // 目标端口
    __u8  protocol;         // 协议
    __u8  state;            // 连接状态
    __u16 flags;            // 标志位
    __u64 packets;          // 包计数
    __u64 bytes;            // 字节计数
    __u64 first_seen;       // 首次看到时间
    __u64 last_seen;        // 最后看到时间
    __u32 timeout;          // 超时时间
};

// eBPF Maps

// Ring Buffer - Netfilter 事件传输
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB Ring Buffer
} netfilter_events SEC(".maps");

// 防火墙规则表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));    // 规则ID
    __uint(value_size, sizeof(struct firewall_rule));
    __uint(max_entries, 1024);
} firewall_rules SEC(".maps");

// 连接跟踪表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));    // 5元组哈希
    __uint(value_size, sizeof(struct connection_track));
    __uint(max_entries, 65536);
} connection_tracks SEC(".maps");

// Netfilter 统计信息
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 32);
} netfilter_stats SEC(".maps");

// Hook 点统计
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 8);  // NF_INET_PRE_ROUTING ~ NF_INET_NUMHOOKS
} hook_stats SEC(".maps");

// NAT 转换表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));    // 原始5元组哈希
    __uint(value_size, sizeof(__u64));  // 转换后5元组哈希
    __uint(max_entries, 16384);
} nat_table SEC(".maps");

// Netfilter 统计键定义
#define NF_STAT_PREROUTING_PACKETS   0
#define NF_STAT_PREROUTING_BYTES     1
#define NF_STAT_LOCALIN_PACKETS      2
#define NF_STAT_LOCALIN_BYTES        3
#define NF_STAT_FORWARD_PACKETS      4
#define NF_STAT_FORWARD_BYTES        5
#define NF_STAT_LOCALOUT_PACKETS     6
#define NF_STAT_LOCALOUT_BYTES       7
#define NF_STAT_POSTROUTING_PACKETS  8
#define NF_STAT_POSTROUTING_BYTES    9
#define NF_STAT_DROPPED_PACKETS      10
#define NF_STAT_DROPPED_BYTES        11
#define NF_STAT_NAT_ENTRIES          12
#define NF_STAT_CONNTRACK_ENTRIES    13

// Helper 函数：更新 netfilter 统计
static inline void update_netfilter_stats(__u32 key, __u64 value) {
    __u64 *stat_ptr = bpf_map_lookup_elem(&netfilter_stats, &key);
    if (stat_ptr) {
        __sync_fetch_and_add(stat_ptr, value);
    } else {
        bpf_map_update_elem(&netfilter_stats, &key, &value, BPF_ANY);
    }
}

// Helper 函数：更新 hook 点统计
static inline void update_hook_stats(__u32 hook, __u64 packets) {
    __u64 *stat_ptr = bpf_map_lookup_elem(&hook_stats, &hook);
    if (stat_ptr) {
        __sync_fetch_and_add(stat_ptr, packets);
    } else {
        bpf_map_update_elem(&hook_stats, &hook, &packets, BPF_ANY);
    }
}

// Helper 函数：发送 netfilter 事件
static inline int send_netfilter_event(struct netfilter_event *event) {
    struct netfilter_event *ringbuf_event;
    
    ringbuf_event = bpf_ringbuf_reserve(&netfilter_events, sizeof(*ringbuf_event), 0);
    if (!ringbuf_event) {
        return -1;
    }
    
    *ringbuf_event = *event;
    bpf_ringbuf_submit(ringbuf_event, 0);
    
    return 0;
}

// Helper 函数：计算5元组哈希
static inline __u64 calculate_flow_hash(__u32 src_ip, __u32 dst_ip, 
                                        __u16 src_port, __u16 dst_port, __u8 proto) {
    __u64 hash = 0;
    hash ^= (__u64)src_ip;
    hash ^= (__u64)dst_ip << 32;
    hash ^= (__u64)src_port << 48;
    hash ^= (__u64)dst_port << 16;
    hash ^= (__u64)proto << 56;
    return hash;
}

// Helper 函数：解析包头信息
static inline int parse_packet_nf(struct __sk_buff *skb, struct nf_packet_info *info) {
    struct iphdr *ip;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 检查 IP 头
    ip = data;
    if ((void *)(ip + 1) > data_end) {
        return -1;
    }
    
    // 基本 IP 信息
    info->src_ip = ip->saddr;
    info->dst_ip = ip->daddr;
    info->protocol = ip->protocol;
    info->tos = ip->tos;
    info->packet_len = bpf_ntohs(ip->tot_len);
    info->frag_off = bpf_ntohs(ip->frag_off);
    info->src_port = 0;
    info->dst_port = 0;
    
    // 解析传输层端口
    if (info->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            info->src_port = bpf_ntohs(tcp->source);
            info->dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (info->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            info->src_port = bpf_ntohs(udp->source);
            info->dst_port = bpf_ntohs(udp->dest);
        }
    }
    
    return 0;
}

// Helper 函数：检查防火墙规则
static inline int check_firewall_rules(struct nf_packet_info *info, __u8 direction) {
    // 简化的规则检查实现
    // 实际应用中需要遍历规则表进行匹配
    
    // 示例：检查是否有匹配的规则
    for (__u32 rule_id = 1; rule_id <= 100; rule_id++) {
        struct firewall_rule *rule = bpf_map_lookup_elem(&firewall_rules, &rule_id);
        if (!rule || !rule->enabled) {
            continue;
        }
        
        // 检查方向
        if (rule->direction != 2 && rule->direction != direction) {
            continue;
        }
        
        // 检查协议
        if (rule->protocol != 0 && rule->protocol != info->protocol) {
            continue;
        }
        
        // 检查源IP
        if (rule->src_ip != 0) {
            if ((info->src_ip & rule->src_mask) != (rule->src_ip & rule->src_mask)) {
                continue;
            }
        }
        
        // 检查目标IP
        if (rule->dst_ip != 0) {
            if ((info->dst_ip & rule->dst_mask) != (rule->dst_ip & rule->dst_mask)) {
                continue;
            }
        }
        
        // 检查端口范围
        if (rule->src_port_min != 0 || rule->src_port_max != 0) {
            if (info->src_port < rule->src_port_min || info->src_port > rule->src_port_max) {
                continue;
            }
        }
        
        if (rule->dst_port_min != 0 || rule->dst_port_max != 0) {
            if (info->dst_port < rule->dst_port_min || info->dst_port > rule->dst_port_max) {
                continue;
            }
        }
        
        // 规则匹配，更新命中统计
        __sync_fetch_and_add(&rule->hit_count, 1);
        __sync_fetch_and_add(&rule->byte_count, info->packet_len);
        
        info->rule_id = (__u8)rule_id;
        return rule->action;
    }
    
    // 默认允许
    return NF_RULE_ALLOW;
}

// Helper 函数：更新连接跟踪
static inline int update_connection_track(struct nf_packet_info *info) {
    __u64 flow_hash = calculate_flow_hash(info->src_ip, info->dst_ip, 
                                         info->src_port, info->dst_port, info->protocol);
    
    struct connection_track *ct = bpf_map_lookup_elem(&connection_tracks, &flow_hash);
    __u64 now = bpf_ktime_get_ns();
    
    if (!ct) {
        // 新连接
        struct connection_track new_ct = {0};
        new_ct.src_ip = info->src_ip;
        new_ct.dst_ip = info->dst_ip;
        new_ct.src_port = info->src_port;
        new_ct.dst_port = info->dst_port;
        new_ct.protocol = info->protocol;
        new_ct.state = CT_STATE_NEW;
        new_ct.packets = 1;
        new_ct.bytes = info->packet_len;
        new_ct.first_seen = now;
        new_ct.last_seen = now;
        new_ct.timeout = now + 300000000000ULL; // 5分钟超时
        
        bpf_map_update_elem(&connection_tracks, &flow_hash, &new_ct, BPF_ANY);
        update_netfilter_stats(NF_STAT_CONNTRACK_ENTRIES, 1);
        return CT_STATE_NEW;
    } else {
        // 已存在连接
        __sync_fetch_and_add(&ct->packets, 1);
        __sync_fetch_and_add(&ct->bytes, info->packet_len);
        ct->last_seen = now;
        
        // 更新连接状态
        if (ct->state == CT_STATE_NEW && ct->packets > 2) {
            ct->state = CT_STATE_ESTABLISHED;
        }
        
        return ct->state;
    }
}

// Netfilter PREROUTING Hook
SEC("tc")
int netfilter_prerouting(struct __sk_buff *skb) {
    struct nf_packet_info packet_info = {0};
    struct netfilter_event event = {0};
    
    // 解析包信息
    if (parse_packet_nf(skb, &packet_info) < 0) {
        return NF_ACCEPT;
    }
    
    packet_info.hook = NF_INET_PRE_ROUTING;
    packet_info.mark = skb->mark;
    
    // 更新连接跟踪
    __u32 conn_state = update_connection_track(&packet_info);
    
    // 检查防火墙规则
    int rule_action = check_firewall_rules(&packet_info, 0); // 入方向
    
    // 决定包的处理方式
    __u8 verdict = NF_VERDICT_ACCEPT;
    if (rule_action == NF_RULE_DENY) {
        verdict = NF_VERDICT_DROP;
    }
    
    // 构造事件
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = NF_EVENT_PREROUTING;
    event.src_ip = packet_info.src_ip;
    event.dst_ip = packet_info.dst_ip;
    event.src_port = packet_info.src_port;
    event.dst_port = packet_info.dst_port;
    event.protocol = packet_info.protocol;
    event.verdict = verdict;
    event.hook_point = NF_INET_PRE_ROUTING;
    event.rule_action = rule_action;
    event.packet_len = packet_info.packet_len;
    event.mark = packet_info.mark;
    event.conn_state = conn_state;
    
    // 发送事件
    send_netfilter_event(&event);
    
    // 更新统计
    update_netfilter_stats(NF_STAT_PREROUTING_PACKETS, 1);
    update_netfilter_stats(NF_STAT_PREROUTING_BYTES, packet_info.packet_len);
    update_hook_stats(NF_INET_PRE_ROUTING, 1);
    
    if (verdict == NF_VERDICT_DROP) {
        update_netfilter_stats(NF_STAT_DROPPED_PACKETS, 1);
        update_netfilter_stats(NF_STAT_DROPPED_BYTES, packet_info.packet_len);
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
