// +build ignore

// NetProbe eBPF VXLAN Monitor - Flannel Traffic Monitoring
// 专门用于监控Kubernetes集群中Flannel框架的Pod间VXLAN流量统计
// 支持VXLAN封装/解封装流量监控和性能分析

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

// VXLAN端口定义 (Flannel默认使用8472端口)
#define VXLAN_PORT 8472
#define VXLAN_HEADER_SIZE 8

// VXLAN头部结构体
struct vxlan_hdr {
    __u8  flags;        // VXLAN标志位
    __u8  reserved[3];  // 保留字段
    __u32 vni;          // VXLAN网络标识符(24位) + 保留位(8位)
} __attribute__((packed));

// Flannel VXLAN流量统计key
struct vxlan_flow_key {
    __u32 outer_src_ip;    // 外层源IP (宿主机IP)
    __u32 outer_dst_ip;    // 外层目标IP (宿主机IP)
    __u32 inner_src_ip;    // 内层源IP (Pod IP)
    __u32 inner_dst_ip;    // 内层目标IP (Pod IP)
    __u32 vni;             // VXLAN网络标识符
    __u16 inner_src_port;  // 内层源端口
    __u16 inner_dst_port;  // 内层目标端口
    __u8  inner_proto;     // 内层协议
    __u8  direction;       // 流量方向: 0=ingress, 1=egress
    __u8  pad[2];          // 填充对齐
} __attribute__((packed));

// VXLAN流量统计信息
struct vxlan_flow_stats {
    __u64 packets;           // 数据包数量
    __u64 bytes;             // 字节数
    __u64 first_seen;        // 首次观察时间
    __u64 last_seen;         // 最后观察时间
    __u32 encap_packets;     // 封装数据包数
    __u32 decap_packets;     // 解封装数据包数
    __u64 encap_bytes;       // 封装字节数
    __u64 decap_bytes;       // 解封装字节数
};

// VXLAN事件结构，用于Ring Buffer传输
struct vxlan_event {
    __u64 timestamp;         // 事件时间戳
    __u32 outer_src_ip;      // 外层源IP
    __u32 outer_dst_ip;      // 外层目标IP
    __u32 inner_src_ip;      // 内层源IP
    __u32 inner_dst_ip;      // 内层目标IP
    __u32 vni;               // VXLAN网络标识符
    __u16 inner_src_port;    // 内层源端口
    __u16 inner_dst_port;    // 内层目标端口
    __u16 packet_len;        // 数据包长度
    __u8  inner_proto;       // 内层协议
    __u8  direction;         // 流量方向
    __u8  event_type;        // 事件类型: 0=正常, 1=新建连接, 2=异常
    __u8  vxlan_flags;       // VXLAN标志位
    __u8  hook_point;        // Hook点: 2=TC_INGRESS, 3=TC_EGRESS
    __u8  pad[3];            // 填充对齐
    __u32 ifindex;           // 网络接口索引
};

// Pod网络信息key (用于Pod IP映射)
struct pod_info_key {
    __u32 pod_ip;            // Pod IP地址
};

// Pod网络信息
struct pod_info {
    __u32 node_ip;           // 节点IP地址
    __u32 vni;               // 所属VXLAN网络
    char  pod_name[64];      // Pod名称
    char  namespace[32];     // 命名空间
    __u64 created_time;      // 创建时间
};

// 基础统计信息结构
struct basic_stats {
    __u64 packets;
    __u64 bytes;
    __u64 errors;
    __u64 drops;
};

// eBPF Maps定义

// VXLAN流量统计Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct vxlan_flow_key);
    __type(value, struct vxlan_flow_stats);
} vxlan_flow_stats SEC(".maps");

// Pod信息映射Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct pod_info_key);
    __type(value, struct pod_info);
} pod_info_map SEC(".maps");

// VXLAN事件Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} vxlan_events SEC(".maps");

// 每个接口的VXLAN统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);           // ifindex
    __type(value, struct basic_stats);
} vxlan_interface_stats SEC(".maps");

// VXLAN网络识别统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);           // VNI
    __type(value, struct basic_stats);
} vxlan_network_stats SEC(".maps");

// 辅助函数：解析内层以太网头部
static __always_inline int parse_inner_ethernet(void *data, void *data_end,
                                               struct ethhdr **inner_eth) {
    *inner_eth = data;
    if ((void *)(*inner_eth + 1) > data_end)
        return -1;
    return 0;
}

// 辅助函数：解析内层IP头部
static __always_inline int parse_inner_ip(void *data, void *data_end,
                                         struct iphdr **inner_ip) {
    *inner_ip = data;
    if ((void *)(*inner_ip + 1) > data_end)
        return -1;
    
    // 检查IP版本
    if ((*inner_ip)->version != 4)
        return -1;
    
    return 0;
}

// 辅助函数：解析内层传输层协议
static __always_inline int parse_inner_transport(struct iphdr *inner_ip,
                                                void *data_end,
                                                __u16 *src_port,
                                                __u16 *dst_port) {
    void *transport_hdr = (void *)inner_ip + (inner_ip->ihl * 4);
    
    if (inner_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_hdr;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
    } else if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_hdr;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *src_port = bpf_ntohs(udp->source);
        *dst_port = bpf_ntohs(udp->dest);
    } else {
        *src_port = 0;
        *dst_port = 0;
    }
    
    return 0;
}

// 辅助函数：处理VXLAN数据包
static __always_inline int process_vxlan_packet(struct __sk_buff *skb,
                                               struct iphdr *outer_ip,
                                               struct udphdr *udp,
                                               __u8 direction) {
    void *data_end = (void *)(long)skb->data_end;
    
    // 计算VXLAN头部位置
    struct vxlan_hdr *vxlan = (void *)udp + sizeof(struct udphdr);
    if ((void *)(vxlan + 1) > data_end)
        return TC_ACT_OK;
    
    // 解析内层以太网头部
    struct ethhdr *inner_eth;
    void *inner_payload = (void *)vxlan + sizeof(struct vxlan_hdr);
    if (parse_inner_ethernet(inner_payload, data_end, &inner_eth) < 0)
        return TC_ACT_OK;
    
    // 检查内层是否为IP包
    if (bpf_ntohs(inner_eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // 解析内层IP头部
    struct iphdr *inner_ip;
    void *inner_ip_data = (void *)inner_eth + sizeof(struct ethhdr);
    if (parse_inner_ip(inner_ip_data, data_end, &inner_ip) < 0)
        return TC_ACT_OK;
    
    // 解析内层传输层端口
    __u16 inner_src_port = 0, inner_dst_port = 0;
    parse_inner_transport(inner_ip, data_end, &inner_src_port, &inner_dst_port);
    
    // 构建VXLAN流量key
    struct vxlan_flow_key flow_key = {
        .outer_src_ip = bpf_ntohl(outer_ip->saddr),
        .outer_dst_ip = bpf_ntohl(outer_ip->daddr),
        .inner_src_ip = bpf_ntohl(inner_ip->saddr),
        .inner_dst_ip = bpf_ntohl(inner_ip->daddr),
        .vni = bpf_ntohl(vxlan->vni) >> 8, // 提取24位VNI
        .inner_src_port = inner_src_port,
        .inner_dst_port = inner_dst_port,
        .inner_proto = inner_ip->protocol,
        .direction = direction,
    };
    
    // 更新流量统计
    struct vxlan_flow_stats *stats = bpf_map_lookup_elem(&vxlan_flow_stats, &flow_key);
    __u64 now = bpf_ktime_get_ns();
    __u16 packet_len = bpf_ntohs(inner_ip->tot_len);
    
    if (stats) {
        stats->packets++;
        stats->bytes += packet_len;
        stats->last_seen = now;
        
        if (direction == 0) { // ingress - 解封装
            stats->decap_packets++;
            stats->decap_bytes += packet_len;
        } else { // egress - 封装
            stats->encap_packets++;
            stats->encap_bytes += packet_len;
        }
    } else {
        struct vxlan_flow_stats new_stats = {
            .packets = 1,
            .bytes = packet_len,
            .first_seen = now,
            .last_seen = now,
            .encap_packets = (direction == 1) ? 1 : 0,
            .decap_packets = (direction == 0) ? 1 : 0,
            .encap_bytes = (direction == 1) ? packet_len : 0,
            .decap_bytes = (direction == 0) ? packet_len : 0,
        };
        bpf_map_update_elem(&vxlan_flow_stats, &flow_key, &new_stats, BPF_ANY);
    }
    
    // 更新接口统计
    __u32 ifindex = skb->ifindex;
    struct basic_stats *if_stats = bpf_map_lookup_elem(&vxlan_interface_stats, &ifindex);
    if (if_stats) {
        if_stats->packets++;
        if_stats->bytes += packet_len;
    } else {
        struct basic_stats new_if_stats = {
            .packets = 1,
            .bytes = packet_len,
            .errors = 0,
            .drops = 0,
        };
        bpf_map_update_elem(&vxlan_interface_stats, &ifindex, &new_if_stats, BPF_ANY);
    }
    
    // 更新VNI统计
    __u32 vni = flow_key.vni;
    struct basic_stats *vni_stats = bpf_map_lookup_elem(&vxlan_network_stats, &vni);
    if (vni_stats) {
        vni_stats->packets++;
        vni_stats->bytes += packet_len;
    } else {
        struct basic_stats new_vni_stats = {
            .packets = 1,
            .bytes = packet_len,
            .errors = 0,
            .drops = 0,
        };
        bpf_map_update_elem(&vxlan_network_stats, &vni, &new_vni_stats, BPF_ANY);
    }
    
    // 发送事件到Ring Buffer (仅对新连接或重要事件)
    if (!stats || (stats->packets % 1000 == 1)) { // 新连接或每1000个包发送一次事件
        struct vxlan_event *event = bpf_ringbuf_reserve(&vxlan_events, 
                                                       sizeof(struct vxlan_event), 0);
        if (event) {
            event->timestamp = now;
            event->outer_src_ip = flow_key.outer_src_ip;
            event->outer_dst_ip = flow_key.outer_dst_ip;
            event->inner_src_ip = flow_key.inner_src_ip;
            event->inner_dst_ip = flow_key.inner_dst_ip;
            event->vni = flow_key.vni;
            event->inner_src_port = flow_key.inner_src_port;
            event->inner_dst_port = flow_key.inner_dst_port;
            event->packet_len = packet_len;
            event->inner_proto = flow_key.inner_proto;
            event->direction = direction;
            event->event_type = stats ? 0 : 1; // 0=正常, 1=新连接
            event->vxlan_flags = vxlan->flags;
            event->hook_point = direction == 0 ? 2 : 3; // TC_INGRESS : TC_EGRESS
            event->ifindex = ifindex;
            
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return TC_ACT_OK;
}

// TC ingress程序 - 监控VXLAN解封装流量
SEC("tc/ingress")
int vxlan_ingress_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 解析以太网头部
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // 检查是否为IP包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // 解析IP头部
    struct iphdr *ip = (void *)eth + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // 检查是否为UDP包
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    // 解析UDP头部
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    // 检查是否为VXLAN端口
    if (bpf_ntohs(udp->dest) != VXLAN_PORT && bpf_ntohs(udp->source) != VXLAN_PORT)
        return TC_ACT_OK;
    
    // 处理VXLAN数据包 (ingress = 解封装)
    return process_vxlan_packet(skb, ip, udp, 0);
}

// TC egress程序 - 监控VXLAN封装流量
SEC("tc/egress")
int vxlan_egress_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 解析以太网头部
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // 检查是否为IP包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // 解析IP头部
    struct iphdr *ip = (void *)eth + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // 检查是否为UDP包
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    // 解析UDP头部
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    // 检查是否为VXLAN端口
    if (bpf_ntohs(udp->dest) != VXLAN_PORT && bpf_ntohs(udp->source) != VXLAN_PORT)
        return TC_ACT_OK;
    
    // 处理VXLAN数据包 (egress = 封装)
    return process_vxlan_packet(skb, ip, udp, 1);
}

char _license[] SEC("license") = "GPL";
