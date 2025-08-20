#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 安全事件类型
#define SECURITY_EVENT_SUSPICIOUS_CONNECTION  1
#define SECURITY_EVENT_PORT_SCAN             2
#define SECURITY_EVENT_DDoS_ATTEMPT          3
#define SECURITY_EVENT_MALICIOUS_PAYLOAD     4

// 安全事件结构
struct security_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u32 severity;
    char  description[64];
};

// 连接跟踪结构
struct connection_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

struct connection_info {
    __u64 first_seen;
    __u64 last_seen;
    __u32 packet_count;
    __u32 byte_count;
    __u8  flags;
};

// 端口扫描检测结构
struct scan_key {
    __u32 src_ip;
    __u32 dst_ip;
};

struct scan_info {
    __u64 first_scan;
    __u64 last_scan;
    __u32 port_count;
    __u16 ports[64];  // 最多记录64个端口
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct connection_key);
    __type(value, struct connection_info);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct scan_key);
    __type(value, struct scan_info);
} port_scans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} security_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} security_stats SEC(".maps");

// 配置参数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} security_config SEC(".maps");

#define CONFIG_SCAN_THRESHOLD       0  // 端口扫描阈值
#define CONFIG_CONNECTION_TIMEOUT   1  // 连接超时时间
#define CONFIG_DDOS_THRESHOLD      2  // DDoS 检测阈值

// 辅助函数：获取配置值
static inline __u32 get_config(__u32 key, __u32 default_value) {
    __u32 *value = bpf_map_lookup_elem(&security_config, &key);
    return value ? *value : default_value;
}

// 辅助函数：更新安全统计
static inline void update_security_stats(__u32 key) {
    __u64 *stat = bpf_map_lookup_elem(&security_stats, &key);
    if (stat) {
        __sync_fetch_and_add(stat, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&security_stats, &key, &initial, BPF_ANY);
    }
}

// 辅助函数：发送安全事件
static inline void send_security_event(__u32 event_type, __u32 src_ip, __u32 dst_ip,
                                     __u16 src_port, __u16 dst_port, __u8 proto,
                                     __u32 severity, const char *description) {
    struct security_event *event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = event_type;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->proto = proto;
    event->severity = severity;
    
    // 复制描述（简化版本）
    __builtin_memset(event->description, 0, sizeof(event->description));
    bpf_probe_read_str(event->description, sizeof(event->description), description);
    
    bpf_ringbuf_submit(event, 0);
    update_security_stats(event_type);
}

// 端口扫描检测
static inline void detect_port_scan(__u32 src_ip, __u32 dst_ip, __u16 dst_port) {
    struct scan_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
    };
    
    struct scan_info *scan = bpf_map_lookup_elem(&port_scans, &key);
    __u64 now = bpf_ktime_get_ns();
    
    if (!scan) {
        // 新的扫描记录
        struct scan_info new_scan = {
            .first_scan = now,
            .last_scan = now,
            .port_count = 1,
        };
        new_scan.ports[0] = dst_port;
        bpf_map_update_elem(&port_scans, &key, &new_scan, BPF_ANY);
        return;
    }
    
    // 检查是否在扫描时间窗口内
    if (now - scan->first_scan > 60000000000ULL) { // 60秒窗口
        // 重置扫描记录
        scan->first_scan = now;
        scan->last_scan = now;
        scan->port_count = 1;
        scan->ports[0] = dst_port;
        return;
    }
    
    // 检查端口是否已经记录
    int found = 0;
    #pragma unroll
    for (int i = 0; i < 64 && i < scan->port_count; i++) {
        if (scan->ports[i] == dst_port) {
            found = 1;
            break;
        }
    }
    
    if (!found && scan->port_count < 64) {
        scan->ports[scan->port_count] = dst_port;
        scan->port_count++;
        scan->last_scan = now;
        
        // 检查是否达到扫描阈值
        __u32 threshold = get_config(CONFIG_SCAN_THRESHOLD, 10);
        if (scan->port_count >= threshold) {
            send_security_event(SECURITY_EVENT_PORT_SCAN, src_ip, dst_ip,
                              0, dst_port, 6, 3, "Port scan detected");
        }
    }
}

// kprobe: 监控 TCP 连接建立
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    
    // 读取源和目标地址信息
    bpf_probe_read(&src_ip, sizeof(src_ip), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&src_port, sizeof(src_port), &sk->__sk_common.skc_num);
    bpf_probe_read(&dst_port, sizeof(dst_port), &sk->__sk_common.skc_dport);
    
    // 端口扫描检测
    detect_port_scan(src_ip, dst_ip, bpf_ntohs(dst_port));
    
    // 记录连接信息
    struct connection_key conn_key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = 6, // TCP
    };
    
    struct connection_info conn_info = {
        .first_seen = bpf_ktime_get_ns(),
        .last_seen = bpf_ktime_get_ns(),
        .packet_count = 1,
        .byte_count = 0,
        .flags = 0,
    };
    
    bpf_map_update_elem(&connections, &conn_key, &conn_info, BPF_ANY);
    
    return 0;
}

// tracepoint: 监控网络数据包
SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx) {
    // 这里可以添加对接收数据包的安全检查
    // 例如检测异常的数据包模式、DDoS 攻击等
    
    return 0;
}

// kprobe: 监控可疑的系统调用
SEC("kprobe/sys_socket")
int trace_socket_creation(struct pt_regs *ctx) {
    int family = (int)PT_REGS_PARM1(ctx);
    int type = (int)PT_REGS_PARM2(ctx);
    int protocol = (int)PT_REGS_PARM3(ctx);
    
    // 检测可疑的 socket 创建模式
    // 例如短时间内大量创建 socket
    
    return 0;
}

char _license[] SEC("license") = "GPL";
