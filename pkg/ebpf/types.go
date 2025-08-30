package ebpf

import (
	"fmt"
	"time"
)

// XDPProgramType XDP程序类型
type XDPProgramType int

const (
	XDPBasicMonitor XDPProgramType = iota
	XDPAdvancedFilter
	XDPLoadBalancer
)

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
	Ifindex   uint32  // 4 bytes - 网络接口索引
	// 总计: 32 bytes (已对齐)
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
	
	return fmt.Sprintf("[%s] %s %s:%d -> %s:%d (%s, %d bytes) at %s",
		direction, protocol, srcIP, ne.SrcPort, dstIP, ne.DstPort,
		protocol, ne.PacketLen, timestamp.Format("15:04:05.000"))
}

// EventHandler 事件处理器接口
type EventHandler interface {
	HandleEvent(event *NetworkEvent) error
	HandleBatch(events []*NetworkEvent) error
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
	DDosBlocked     uint64 // DDoS攻击被阻止的数量
	SecurityEvents  uint64 // 安全事件数量
	XDPDropped      uint64 // XDP层丢弃的包数量
	BlacklistedIPs  uint64 // 黑名单IP数量
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
