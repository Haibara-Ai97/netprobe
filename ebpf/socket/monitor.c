//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../include" --target=amd64 SocketMonitor monitor.c

// NetProbe eBPF Socket Monitor
// Socket 层网络连接监控，提供连接建立、数据传输、连接状态跟踪
// 支持 TCP/UDP 连接的全生命周期监控

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Socket 连接信息结构体
struct socket_conn_info {
    __u32 pid;              // 进程ID
    __u32 tid;              // 线程ID
    __u32 uid;              // 用户ID
    __u32 src_ip;           // 源IP地址
    __u32 dst_ip;           // 目标IP地址
    __u16 src_port;         // 源端口
    __u16 dst_port;         // 目标端口
    __u8  protocol;         // 协议类型 (TCP/UDP)
    __u8  family;           // 地址族 (AF_INET/AF_INET6)
    __u16 state;            // 连接状态
    char  comm[16];         // 进程名称
} __attribute__((packed));

// Socket 事件结构体 - Ring Buffer 传输
struct socket_event {
    __u64 timestamp;        // 事件时间戳
    __u32 event_type;       // 事件类型: 0=connect, 1=accept, 2=close, 3=send, 4=recv
    __u32 pid;              // 进程ID
    __u32 tid;              // 线程ID
    __u32 src_ip;           // 源IP
    __u32 dst_ip;           // 目标IP
    __u16 src_port;         // 源端口
    __u16 dst_port;         // 目标端口
    __u8  protocol;         // 协议
    __u8  family;           // 地址族
    __u16 state;            // 连接状态
    __u32 bytes_sent;       // 发送字节数（send/recv事件）
    __u32 bytes_recv;       // 接收字节数
    __u32 duration_us;      // 连接持续时间（微秒）
    char  comm[16];         // 进程名
    __u32 error_code;       // 错误码
} __attribute__((packed));

// Socket 统计信息
struct socket_stats {
    __u64 total_connections;    // 总连接数
    __u64 active_connections;   // 活跃连接数
    __u64 failed_connections;   // 失败连接数
    __u64 bytes_sent;          // 总发送字节数
    __u64 bytes_received;      // 总接收字节数
    __u64 connection_duration; // 连接总时长
};

// eBPF Maps

// Ring Buffer - Socket 事件传输
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB Ring Buffer
} socket_events SEC(".maps");

// Socket 连接跟踪表 - 维护活跃连接状态
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));    // socket 指针作为 key
    __uint(value_size, sizeof(struct socket_conn_info));
    __uint(max_entries, 65536);
} socket_connections SEC(".maps");

// Socket 统计信息
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 16);
} socket_stats SEC(".maps");

// Per-process socket 统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));    // PID
    __uint(value_size, sizeof(struct socket_stats));
    __uint(max_entries, 1024);
} process_socket_stats SEC(".maps");

// Socket 事件类型定义
#define SOCKET_EVENT_CONNECT    0
#define SOCKET_EVENT_ACCEPT     1
#define SOCKET_EVENT_CLOSE      2
#define SOCKET_EVENT_SEND       3
#define SOCKET_EVENT_RECV       4
#define SOCKET_EVENT_ERROR      5

// Socket 统计键定义
#define SOCKET_STAT_TOTAL_CONN      0
#define SOCKET_STAT_ACTIVE_CONN     1
#define SOCKET_STAT_FAILED_CONN     2
#define SOCKET_STAT_BYTES_SENT      3
#define SOCKET_STAT_BYTES_RECV      4
#define SOCKET_STAT_CONN_DURATION   5

// Helper 函数：更新 socket 统计信息
static inline void update_socket_stats(__u32 key, __u64 value) {
    __u64 *stat_ptr = bpf_map_lookup_elem(&socket_stats, &key);
    if (stat_ptr) {
        __sync_fetch_and_add(stat_ptr, value);
    } else {
        bpf_map_update_elem(&socket_stats, &key, &value, BPF_ANY);
    }
}

// Helper 函数：发送 socket 事件
static inline int send_socket_event(struct socket_event *event) {
    struct socket_event *ringbuf_event;
    
    ringbuf_event = bpf_ringbuf_reserve(&socket_events, sizeof(*ringbuf_event), 0);
    if (!ringbuf_event) {
        return -1;
    }
    
    *ringbuf_event = *event;
    bpf_ringbuf_submit(ringbuf_event, 0);
    
    return 0;
}

// Helper 函数：获取进程信息
static inline void get_process_info(__u32 *pid, __u32 *tid, char *comm) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    *pid = pid_tgid >> 32;
    *tid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(comm, 16);
}

// Helper 函数：从 socket 结构提取地址信息
static inline int extract_socket_info(struct sock *sk, struct socket_conn_info *info) {
    if (!sk || !info) {
        return -1;
    }
    
    // 读取地址族
    __u16 family;
    if (bpf_core_read(&family, sizeof(family), &sk->sk_family) != 0) {
        return -1;
    }
    info->family = (__u8)family;
    
    // 只处理 IPv4
    if (family != AF_INET) {
        return -1;
    }
    
    // 读取协议类型
    __u8 protocol;
    if (bpf_core_read(&protocol, sizeof(protocol), &sk->sk_protocol) != 0) {
        return -1;
    }
    info->protocol = protocol;
    
    // 读取本地地址和端口
    if (bpf_core_read(&info->src_ip, sizeof(info->src_ip), &sk->sk_rcv_saddr) != 0) {
        return -1;
    }
    if (bpf_core_read(&info->src_port, sizeof(info->src_port), &sk->sk_num) != 0) {
        return -1;
    }
    
    // 读取远程地址和端口
    if (bpf_core_read(&info->dst_ip, sizeof(info->dst_ip), &sk->sk_daddr) != 0) {
        return -1;
    }
    if (bpf_core_read(&info->dst_port, sizeof(info->dst_port), &sk->sk_dport) != 0) {
        return -1;
    }
    
    // 转换端口字节序
    info->dst_port = bpf_ntohs(info->dst_port);
    
    // 读取连接状态
    __u8 state;
    if (bpf_core_read(&state, sizeof(state), &sk->sk_state) != 0) {
        return -1;
    }
    info->state = (__u16)state;
    
    return 0;
}

// TCP connect() 系统调用跟踪
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct socket_conn_info conn_info = {0};
    struct socket_event event = {0};
    
    // 获取进程信息
    get_process_info(&conn_info.pid, &conn_info.tid, conn_info.comm);
    conn_info.uid = bpf_get_current_uid_gid();
    
    // 提取 socket 信息
    if (extract_socket_info(sk, &conn_info) < 0) {
        return 0;
    }
    
    // 存储连接信息到 map
    __u64 sock_key = (__u64)sk;
    bpf_map_update_elem(&socket_connections, &sock_key, &conn_info, BPF_ANY);
    
    // 构造事件
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = SOCKET_EVENT_CONNECT;
    event.pid = conn_info.pid;
    event.tid = conn_info.tid;
    event.src_ip = conn_info.src_ip;
    event.dst_ip = conn_info.dst_ip;
    event.src_port = conn_info.src_port;
    event.dst_port = conn_info.dst_port;
    event.protocol = conn_info.protocol;
    event.family = conn_info.family;
    event.state = conn_info.state;
    __builtin_memcpy(event.comm, conn_info.comm, 16);
    
    // 发送事件
    send_socket_event(&event);
    
    // 更新统计
    update_socket_stats(SOCKET_STAT_TOTAL_CONN, 1);
    update_socket_stats(SOCKET_STAT_ACTIVE_CONN, 1);
    
    return 0;
}

// TCP accept() 系统调用跟踪
SEC("kprobe/inet_csk_accept")
int trace_tcp_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct socket_conn_info conn_info = {0};
    struct socket_event event = {0};
    
    // 获取进程信息
    get_process_info(&conn_info.pid, &conn_info.tid, conn_info.comm);
    conn_info.uid = bpf_get_current_uid_gid();
    
    // 提取 socket 信息
    if (extract_socket_info(sk, &conn_info) < 0) {
        return 0;
    }
    
    // 存储连接信息
    __u64 sock_key = (__u64)sk;
    bpf_map_update_elem(&socket_connections, &sock_key, &conn_info, BPF_ANY);
    
    // 构造事件
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = SOCKET_EVENT_ACCEPT;
    event.pid = conn_info.pid;
    event.tid = conn_info.tid;
    event.src_ip = conn_info.src_ip;
    event.dst_ip = conn_info.dst_ip;
    event.src_port = conn_info.src_port;
    event.dst_port = conn_info.dst_port;
    event.protocol = conn_info.protocol;
    event.family = conn_info.family;
    event.state = conn_info.state;
    __builtin_memcpy(event.comm, conn_info.comm, 16);
    
    // 发送事件
    send_socket_event(&event);
    
    // 更新统计
    update_socket_stats(SOCKET_STAT_TOTAL_CONN, 1);
    update_socket_stats(SOCKET_STAT_ACTIVE_CONN, 1);
    
    return 0;
}

// Socket close 跟踪
SEC("kprobe/tcp_close")
int trace_tcp_close(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u64 sock_key = (__u64)sk;
    struct socket_event event = {0};
    
    // 查找连接信息
    struct socket_conn_info *conn_info = bpf_map_lookup_elem(&socket_connections, &sock_key);
    if (!conn_info) {
        return 0;
    }
    
    // 构造关闭事件
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = SOCKET_EVENT_CLOSE;
    event.pid = conn_info->pid;
    event.tid = conn_info->tid;
    event.src_ip = conn_info->src_ip;
    event.dst_ip = conn_info->dst_ip;
    event.src_port = conn_info->src_port;
    event.dst_port = conn_info->dst_port;
    event.protocol = conn_info->protocol;
    event.family = conn_info->family;
    event.state = conn_info->state;
    __builtin_memcpy(event.comm, conn_info->comm, 16);
    
    // 发送事件
    send_socket_event(&event);
    
    // 从 map 中删除连接
    bpf_map_delete_elem(&socket_connections, &sock_key);
    
    // 更新统计
    update_socket_stats(SOCKET_STAT_ACTIVE_CONN, -1);
    
    return 0;
}

// TCP 发送数据跟踪
SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    __u64 sock_key = (__u64)sk;
    
    // 查找连接信息
    struct socket_conn_info *conn_info = bpf_map_lookup_elem(&socket_connections, &sock_key);
    if (!conn_info) {
        return 0;
    }
    
    // 构造发送事件
    struct socket_event event = {0};
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = SOCKET_EVENT_SEND;
    event.pid = conn_info->pid;
    event.tid = conn_info->tid;
    event.src_ip = conn_info->src_ip;
    event.dst_ip = conn_info->dst_ip;
    event.src_port = conn_info->src_port;
    event.dst_port = conn_info->dst_port;
    event.protocol = conn_info->protocol;
    event.family = conn_info->family;
    event.bytes_sent = (__u32)size;
    __builtin_memcpy(event.comm, conn_info->comm, 16);
    
    // 发送事件
    send_socket_event(&event);
    
    // 更新统计
    update_socket_stats(SOCKET_STAT_BYTES_SENT, size);
    
    return 0;
}

// TCP 接收数据跟踪
SEC("kprobe/tcp_recvmsg")
int trace_tcp_recv(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    __u64 sock_key = (__u64)sk;
    
    // 查找连接信息
    struct socket_conn_info *conn_info = bpf_map_lookup_elem(&socket_connections, &sock_key);
    if (!conn_info) {
        return 0;
    }
    
    // 构造接收事件
    struct socket_event event = {0};
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = SOCKET_EVENT_RECV;
    event.pid = conn_info->pid;
    event.tid = conn_info->tid;
    event.src_ip = conn_info->src_ip;
    event.dst_ip = conn_info->dst_ip;
    event.src_port = conn_info->src_port;
    event.dst_port = conn_info->dst_port;
    event.protocol = conn_info->protocol;
    event.family = conn_info->family;
    event.bytes_recv = (__u32)size;
    __builtin_memcpy(event.comm, conn_info->comm, 16);
    
    // 发送事件
    send_socket_event(&event);
    
    // 更新统计
    update_socket_stats(SOCKET_STAT_BYTES_RECV, size);
    
    return 0;
}

// UDP 发送跟踪
SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    
    struct socket_conn_info conn_info = {0};
    struct socket_event event = {0};
    
    // 获取进程信息
    get_process_info(&conn_info.pid, &conn_info.tid, conn_info.comm);
    
    // 提取 socket 信息
    if (extract_socket_info(sk, &conn_info) < 0) {
        return 0;
    }
    
    // 构造发送事件
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = SOCKET_EVENT_SEND;
    event.pid = conn_info.pid;
    event.tid = conn_info.tid;
    event.src_ip = conn_info.src_ip;
    event.dst_ip = conn_info.dst_ip;
    event.src_port = conn_info.src_port;
    event.dst_port = conn_info.dst_port;
    event.protocol = conn_info.protocol;
    event.family = conn_info.family;
    event.bytes_sent = (__u32)size;
    __builtin_memcpy(event.comm, conn_info.comm, 16);
    
    // 发送事件
    send_socket_event(&event);
    
    // 更新统计
    update_socket_stats(SOCKET_STAT_BYTES_SENT, size);
    
    return 0;
}

// UDP 接收跟踪
SEC("kprobe/udp_recvmsg")
int trace_udp_recv(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    
    struct socket_conn_info conn_info = {0};
    struct socket_event event = {0};
    
    // 获取进程信息
    get_process_info(&conn_info.pid, &conn_info.tid, conn_info.comm);
    
    // 提取 socket 信息
    if (extract_socket_info(sk, &conn_info) < 0) {
        return 0;
    }
    
    // 构造接收事件
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = SOCKET_EVENT_RECV;
    event.pid = conn_info.pid;
    event.tid = conn_info.tid;
    event.src_ip = conn_info.src_ip;
    event.dst_ip = conn_info.dst_ip;
    event.src_port = conn_info.src_port;
    event.dst_port = conn_info.dst_port;
    event.protocol = conn_info.protocol;
    event.family = conn_info.family;
    event.bytes_recv = (__u32)size;
    __builtin_memcpy(event.comm, conn_info.comm, 16);
    
    // 发送事件
    send_socket_event(&event);
    
    // 更新统计
    update_socket_stats(SOCKET_STAT_BYTES_RECV, size);
    
    return 0;
}

char _license[] SEC("license") = "GPL";
