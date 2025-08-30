// NetProbe eBPF 公共头文件
// 包含所有 eBPF 程序需要的公共定义和结构体

#ifndef __NETPROBE_COMMON_H__
#define __NETPROBE_COMMON_H__

// 基础内核头文件
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// BPF 辅助函数头文件
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 公共常量定义
#define ETH_P_IP    0x0800
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

// 地址族定义
#define AF_INET     2
#define AF_INET6    10

// Netfilter hook 点定义
#define NF_INET_PRE_ROUTING     0
#define NF_INET_LOCAL_IN        1
#define NF_INET_FORWARD         2
#define NF_INET_LOCAL_OUT       3
#define NF_INET_POST_ROUTING    4

// Netfilter 判决结果
#define NF_DROP     0
#define NF_ACCEPT   1
#define NF_STOLEN   2
#define NF_QUEUE    3
#define NF_REPEAT   4
#define NF_STOP     5

// XDP 返回值
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

// TC 返回值
#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK       0
#define TC_ACT_RECLASSIFY   1
#define TC_ACT_SHOT     2
#define TC_ACT_PIPE     3
#define TC_ACT_STOLEN   4
#define TC_ACT_QUEUED   5
#define TC_ACT_REPEAT   6
#define TC_ACT_REDIRECT 7

// 公共结构体定义

// IPv4 地址结构
struct ipv4_addr {
    __u32 addr;
} __attribute__((packed));

// 基础网络流标识
struct basic_flow {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
} __attribute__((packed));

// 时间戳结构
struct timestamp_info {
    __u64 first_seen;
    __u64 last_seen;
    __u64 duration;
} __attribute__((packed));

// 统计信息结构
struct basic_stats {
    __u64 packets;
    __u64 bytes;
    __u64 errors;
    __u64 drops;
} __attribute__((packed));

// 网络接口信息
struct interface_info {
    __u32 ifindex;
    __u32 flags;
    __u32 mtu;
    __u8  name[16];
} __attribute__((packed));

// 进程信息结构
struct process_info {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    char  comm[16];
} __attribute__((packed));

// 公共辅助宏

// 字节序转换宏
#define ntohl(x) bpf_ntohl(x)
#define ntohs(x) bpf_ntohs(x)
#define htonl(x) bpf_htonl(x)
#define htons(x) bpf_htons(x)

// 内存拷贝宏
#define memcpy(dst, src, size) __builtin_memcpy(dst, src, size)
#define memset(dst, val, size) __builtin_memset(dst, val, size)

// 原子操作宏
#define atomic_add(ptr, val) __sync_fetch_and_add(ptr, val)
#define atomic_sub(ptr, val) __sync_fetch_and_sub(ptr, val)

// 时间相关宏
#define NS_PER_SEC      1000000000ULL
#define NS_PER_MS       1000000ULL
#define NS_PER_US       1000ULL

// 缓冲区大小定义
#define MAX_PACKET_SIZE     1500
#define MAX_FLOW_ENTRIES    65536
#define MAX_INTERFACES      256
#define MAX_PROCESSES       1024

// 调试和日志宏
#ifdef DEBUG
#define bpf_debug(fmt, args...) bpf_trace_printk(fmt, sizeof(fmt), ##args)
#else
#define bpf_debug(fmt, args...)
#endif

// 错误码定义
#define NETPROBE_OK             0
#define NETPROBE_ERROR         -1
#define NETPROBE_EINVAL        -2
#define NETPROBE_ENOMEM        -3
#define NETPROBE_ENOENT        -4
#define NETPROBE_EEXIST        -5

// 公共辅助函数声明
static inline __u64 get_timestamp_ns(void) {
    return bpf_ktime_get_ns();
}

static inline __u32 get_current_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

static inline __u32 get_current_tid(void) {
    return bpf_get_current_pid_tgid() & 0xFFFFFFFF;
}

static inline __u32 get_current_uid(void) {
    return bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

static inline int get_current_comm(char *comm, int size) {
    return bpf_get_current_comm(comm, size);
}

// 网络地址转换函数
static inline void ip_to_str(__u32 ip, char *str) {
    // 简化的 IP 地址转换，实际实现可能更复杂
    str[0] = (ip & 0xFF) + '0';
    str[1] = '.';
    str[2] = ((ip >> 8) & 0xFF) + '0';
    str[3] = '.';
    str[4] = ((ip >> 16) & 0xFF) + '0';
    str[5] = '.';
    str[6] = ((ip >> 24) & 0xFF) + '0';
    str[7] = '\0';
}

// 哈希计算函数
static inline __u32 hash_flow(struct basic_flow *flow) {
    __u32 hash = 0;
    hash ^= flow->src_ip;
    hash ^= flow->dst_ip;
    hash ^= ((__u32)flow->src_port << 16) | flow->dst_port;
    hash ^= (__u32)flow->protocol;
    return hash;
}

// 范围检查函数
static inline int in_range(__u32 value, __u32 min, __u32 max) {
    return (value >= min && value <= max);
}

// 位操作函数
static inline int is_bit_set(__u32 value, int bit) {
    return (value & (1U << bit)) != 0;
}

static inline __u32 set_bit(__u32 value, int bit) {
    return value | (1U << bit);
}

static inline __u32 clear_bit(__u32 value, int bit) {
    return value & ~(1U << bit);
}

#endif /* __NETPROBE_COMMON_H__ */
