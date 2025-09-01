package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// XDPProgramType XDP程序类型
type XDPProgramType int

const (
	XDPBasicMonitor XDPProgramType = iota
	XDPAdvancedFilter
	XDPLoadBalancer
)

// HookPoint 挂载点类型
type HookPoint uint8

const (
	HookXDP       HookPoint = 1
	HookTCIngress HookPoint = 2
	HookTCEgress  HookPoint = 3
	HookNetfilter HookPoint = 4 // 预留
	HookSocket    HookPoint = 5 // 预留
)

// String 返回挂载点名称
func (h HookPoint) String() string {
	switch h {
	case HookXDP:
		return "XDP"
	case HookTCIngress:
		return "TC_INGRESS"
	case HookTCEgress:
		return "TC_EGRESS"
	case HookNetfilter:
		return "NETFILTER"
	case HookSocket:
		return "SOCKET"
	default:
		return "UNKNOWN"
	}
}

// EventType 事件类型常量
const (
	EventTypeNormal      = 0
	EventTypeAnomaly     = 1
	EventTypeSecurity    = 2
	EventTypeDDoS        = 3
	EventTypeLoadBalance = 4
)

// NetworkEvent Ring Buffer 事件结构体（与 eBPF 程序中的结构体对应）
type NetworkEvent struct {
	Timestamp uint64  // 8 bytes - 事件时间戳（纳秒）
	SrcIP     uint32  // 4 bytes - 源IP地址
	DstIP     uint32  // 4 bytes - 目标IP地址
	SrcPort   uint16  // 2 bytes - 源端口
	DstPort   uint16  // 2 bytes - 目标端口
	PacketLen uint16  // 2 bytes - 包长度
	Protocol  uint8   // 1 byte  - 协议类型
	Direction uint8   // 1 byte  - 流量方向 (0=ingress, 1=egress)
	TCPFlags  uint8   // 1 byte  - TCP标志位
	EventType uint8   // 1 byte  - 事件类型
	HookPoint uint8   // 1 byte  - 挂载点类型
	_         [3]byte // 3 bytes - 填充对齐
	Ifindex   uint32  // 4 bytes - 网络接口索引
	// 总计: 36 bytes (已对齐)
}

// SocketEvent Socket层事件结构体（与 eBPF 程序中的结构体对应）
type SocketEvent struct {
	Timestamp  uint64    // 8 bytes - 事件时间戳（纳秒）
	EventType  uint32    // 4 bytes - 事件类型: 0=connect, 1=accept, 2=close, 3=send, 4=recv
	PID        uint32    // 4 bytes - 进程ID
	TID        uint32    // 4 bytes - 线程ID
	SrcIP      uint32    // 4 bytes - 源IP
	DstIP      uint32    // 4 bytes - 目标IP
	SrcPort    uint16    // 2 bytes - 源端口
	DstPort    uint16    // 2 bytes - 目标端口
	Protocol   uint8     // 1 byte  - 协议
	Family     uint8     // 1 byte  - 地址族
	State      uint16    // 2 bytes - 连接状态
	BytesSent  uint32    // 4 bytes - 发送字节数
	BytesRecv  uint32    // 4 bytes - 接收字节数
	DurationUs uint32    // 4 bytes - 连接持续时间（微秒）
	Comm       [16]byte  // 16 bytes - 进程名
	ErrorCode  uint32    // 4 bytes - 错误码
	// 总计: 72 bytes
}

// String 格式化显示Socket事件
func (se *SocketEvent) String() string {
	srcIP := intToIP(se.SrcIP)
	dstIP := intToIP(se.DstIP)
	protocol := getProtocolName(se.Protocol)
	timestamp := time.Unix(0, int64(se.Timestamp))
	comm := string(se.Comm[:])
	
	eventTypes := []string{"CONNECT", "ACCEPT", "CLOSE", "SEND", "RECV"}
	eventType := "UNKNOWN"
	if se.EventType < uint32(len(eventTypes)) {
		eventType = eventTypes[se.EventType]
	}

	return fmt.Sprintf("[SOCKET|%s] PID:%d %s %s:%d -> %s:%d (%s) at %s",
		eventType, se.PID, protocol, srcIP, se.SrcPort, dstIP, se.DstPort,
		comm, timestamp.Format("15:04:05.000"))
}

// SocketConnInfo Socket连接信息结构体（与 eBPF 程序中的结构体对应）
type SocketConnInfo struct {
	PID      uint32    // 4 bytes - 进程ID
	TID      uint32    // 4 bytes - 线程ID
	UID      uint32    // 4 bytes - 用户ID
	SrcIP    uint32    // 4 bytes - 源IP地址
	DstIP    uint32    // 4 bytes - 目标IP地址
	SrcPort  uint16    // 2 bytes - 源端口
	DstPort  uint16    // 2 bytes - 目标端口
	Protocol uint8     // 1 byte  - 协议类型 (TCP/UDP)
	Family   uint8     // 1 byte  - 地址族 (AF_INET/AF_INET6)
	State    uint16    // 2 bytes - 连接状态
	Comm     [16]byte  // 16 bytes - 进程名称
	// 总计: 48 bytes
}

// String 格式化显示网络事件
func (ne *NetworkEvent) String() string {
	srcIP := intToIP(ne.SrcIP)
	dstIP := intToIP(ne.DstIP)
	direction := "INGRESS"
	if ne.Direction == 1 {
		direction = "EGRESS"
	}
	protocol := getProtocolName(ne.Protocol)
	timestamp := time.Unix(0, int64(ne.Timestamp))
	hookPoint := HookPoint(ne.HookPoint).String()

	return fmt.Sprintf("[%s|%s] %s %s:%d -> %s:%d (%s, %d bytes) at %s",
		direction, hookPoint, protocol, srcIP, ne.SrcPort, dstIP, ne.DstPort,
		protocol, ne.PacketLen, timestamp.Format("15:04:05.000"))
}

// EventHandler 事件处理器接口
type EventHandler interface {
	// 获取处理器名称
	GetName() string
	// 获取支持的钩子点
	GetSupportedHooks() []HookPoint
	// 处理单个事件
	HandleEvent(event *NetworkEvent) error
	// 处理批量事件
	HandleBatch(events []*NetworkEvent) error
	// 获取查询接口
	GetQueryInterface() QueryInterface
}

// QueryInterface 查询接口，提供流量信息查询功能
type QueryInterface interface {
	// 获取总体统计信息
	GetTotalStats() *TrafficStats
	// 获取指定钩子点的统计信息
	GetHookStats(hook HookPoint) *TrafficStats
	// 获取协议分布统计
	GetProtocolDistribution() map[uint8]uint64
	// 获取端口统计
	GetPortStats() map[uint16]uint64
	// 重置统计信息
	ResetStats()
}

// RingBufferReader Ring Buffer读取器
type RingBufferReader struct {
	reader           *ringbuf.Reader
	isRunning        bool
	stopCh           chan struct{}
	handlers         []EventHandler
	mutex            sync.RWMutex
	eventChan        chan *NetworkEvent
	batchChan        chan []*NetworkEvent
	batchSize        int
	batchTimeout     time.Duration
	ctx              context.Context
	cancel           context.CancelFunc
	eventsRead       uint64
	eventsDropped    uint64
	batchesProcessed uint64
}

// TrafficStats 流量统计信息
type TrafficStats struct {
	PacketCount   uint64            // 数据包计数
	ByteCount     uint64            // 字节计数
	ProtocolStats map[uint8]uint64  // 协议统计
	PortStats     map[uint16]uint64 // 端口统计
	FirstSeen     time.Time         // 首次见到流量的时间
	LastSeen      time.Time         // 最后见到流量的时间
}

// NewTrafficStats 创建新的流量统计
func NewTrafficStats() *TrafficStats {
	return &TrafficStats{
		ProtocolStats: make(map[uint8]uint64),
		PortStats:     make(map[uint16]uint64),
		FirstSeen:     time.Now(),
		LastSeen:      time.Now(),
	}
}

// Clone 克隆流量统计
func (ts *TrafficStats) Clone() *TrafficStats {
	result := &TrafficStats{
		PacketCount:   ts.PacketCount,
		ByteCount:     ts.ByteCount,
		ProtocolStats: make(map[uint8]uint64),
		PortStats:     make(map[uint16]uint64),
		FirstSeen:     ts.FirstSeen,
		LastSeen:      ts.LastSeen,
	}

	for k, v := range ts.ProtocolStats {
		result.ProtocolStats[k] = v
	}
	for k, v := range ts.PortStats {
		result.PortStats[k] = v
	}

	return result
}

// TCDeviceKey TC 设备统计键
type TCDeviceKey struct {
	Ifindex   uint32
	Direction uint32 // 0=ingress, 1=egress
	StatType  uint32 // 0=packets, 1=bytes
}

// FlowKey 流量键
type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Padding  [3]uint8
}

// SecurityStats 安全统计信息
type SecurityStats struct {
	DDosBlocked    uint64 // DDoS攻击被阻止的数量
	SecurityEvents uint64 // 安全事件数量
	XDPDropped     uint64 // XDP层丢弃的包数量
	BlacklistedIPs uint64 // 黑名单IP数量
}

// LoadBalancerStats 负载均衡统计信息
type LoadBalancerStats struct {
	LBDecisions  uint64            // 负载均衡决策次数
	TargetCounts map[uint32]uint64 // 每个目标接口的包数量
}

// GlobalStats 全局统计信息
type GlobalStats struct {
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
	Timestamp time.Time
}

// String 格式化显示全局统计
func (gs *GlobalStats) String() string {
	return fmt.Sprintf("RX: %d pkts/%s, TX: %d pkts/%s",
		gs.RxPackets, formatBytes(gs.RxBytes),
		gs.TxPackets, formatBytes(gs.TxBytes))
}

// RingBufferConfig Ring Buffer 配置
type RingBufferConfig struct {
	EnableXDPEvents      bool // 启用 XDP 事件
	EnableTCEvents       bool // 启用 TC 事件
	EnableDetailedEvents bool // 启用详细事件
}

// 辅助函数
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, ip>>24)
}

func getProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Proto-%d", proto)
	}
}

// formatBytes 格式化字节数
func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// RingBufferReader methods (placeholders for now)
func (r *RingBufferReader) readEvents() {
	// Placeholder - implementation should be moved from other files
}

func (r *RingBufferReader) batchProcessor() {
	// Placeholder - implementation should be moved from other files
}
