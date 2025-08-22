package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" --target=amd64 NetworkMonitor ../../ebpf/network/monitor.c

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

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

// PacketInfo 数据包信息
type PacketInfo struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	PacketSize uint16
	Timestamp  uint64
}

// Bpf2goLoader 使用 bpf2go 生成的代码
type Bpf2goLoader struct {
	objs  NetworkMonitorObjects
	links []link.Link
}

// NewBpf2goLoader 创建 bpf2go 加载器
func NewBpf2goLoader() *Bpf2goLoader {
	return &Bpf2goLoader{}
}

// LoadPrograms 加载 bpf2go 生成的程序
func (bl *Bpf2goLoader) LoadPrograms() error {
	// 移除内存锁限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// 加载预编译的 eBPF 程序
	if err := loadNetworkMonitorObjects(&bl.objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}

	fmt.Println("✅ NetworkMonitor objects loaded successfully")
	fmt.Printf("📋 Loaded programs: XDP=%v, TC_Egress=%v, TC_Ingress=%v\n",
		bl.objs.NetworkMonitorXdp != nil,
		bl.objs.NetworkMonitorTcEgress != nil,
		bl.objs.NetworkMonitorTcIngress != nil)

	return nil
}

// AttachNetworkPrograms 附加网络监控程序
func (bl *Bpf2goLoader) AttachNetworkPrograms(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", interfaceName, err)
	}

	fmt.Printf("🔗 Attaching to interface %s (index: %d)\n", interfaceName, iface.Index)

	// 附加 XDP 程序
	if bl.objs.NetworkMonitorXdp != nil {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   bl.objs.NetworkMonitorXdp,
			Interface: iface.Index,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP to %s: %w", interfaceName, err)
		}
		bl.links = append(bl.links, l)
		fmt.Printf("✅ XDP program attached to %s\n", interfaceName)
	}

	// TC 程序需要手动附加（显示提示信息）
	if bl.objs.NetworkMonitorTcEgress != nil {
		fmt.Printf("💡 TC egress program available (manual setup required):\n")
		fmt.Printf("   sudo tc qdisc add dev %s clsact\n", interfaceName)
		fmt.Printf("   sudo tc filter add dev %s egress bpf object-file <compiled.o> section tc\n", interfaceName)
	}

	if bl.objs.NetworkMonitorTcIngress != nil {
		fmt.Printf("💡 TC ingress program available (manual setup required)\n")
	}

	return nil
}

// GetStats 获取统计信息
func (bl *Bpf2goLoader) GetStats() (map[string]uint64, error) {
	stats := make(map[string]uint64)

	// 读取包计数统计
	keys := []uint32{0, 1, 2, 3} // STAT_RX_PACKETS, STAT_TX_PACKETS, STAT_RX_BYTES, STAT_TX_BYTES
	names := []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes"}

	for i, key := range keys {
		var value uint64
		if err := bl.objs.PacketStats.Lookup(key, &value); err != nil {
			// 如果 key 不存在，设置为 0
			value = 0
		}
		stats[names[i]] = value
	}

	return stats, nil
}

// GetPacketStatsMap 获取包统计 Map（用于用户空间读取）
func (bl *Bpf2goLoader) GetPacketStatsMap() *NetworkMonitorMapPacketStats {
	return bl.objs.PacketStats
}

// GetFlowStatsMap 获取流统计 Map
func (bl *Bpf2goLoader) GetFlowStatsMap() *NetworkMonitorMapFlowStats {
	return bl.objs.FlowStats
}

// GetTcDeviceStatsMap 获取 TC 设备统计 Map
func (bl *Bpf2goLoader) GetTcDeviceStatsMap() *NetworkMonitorMapTcDeviceStats {
	return bl.objs.TcDeviceStats
}

// ReadGlobalStats 读取全局统计信息
func (bl *Bpf2goLoader) ReadGlobalStats() (*GlobalStats, error) {
	stats := &GlobalStats{}

	// 读取 RX 包数
	if err := bl.objs.PacketStats.Lookup(uint32(0), &stats.RxPackets); err != nil {
		stats.RxPackets = 0
	}

	// 读取 TX 包数
	if err := bl.objs.PacketStats.Lookup(uint32(1), &stats.TxPackets); err != nil {
		stats.TxPackets = 0
	}

	// 读取 RX 字节数
	if err := bl.objs.PacketStats.Lookup(uint32(2), &stats.RxBytes); err != nil {
		stats.RxBytes = 0
	}

	// 读取 TX 字节数
	if err := bl.objs.PacketStats.Lookup(uint32(3), &stats.TxBytes); err != nil {
		stats.TxBytes = 0
	}

	stats.Timestamp = time.Now()
	return stats, nil
}

// ReadTCDeviceStats 读取 TC 设备统计信息
func (bl *Bpf2goLoader) ReadTCDeviceStats() (map[TCDeviceKey]uint64, error) {
	stats := make(map[TCDeviceKey]uint64)

	// 遍历 TC 设备统计 Map
	var key TCDeviceKey
	var value uint64

	iter := bl.objs.TcDeviceStats.Iterate()
	for iter.Next(&key, &value) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating TC device stats: %w", err)
	}

	return stats, nil
}

// ReadFlowStats 读取流量统计信息
func (bl *Bpf2goLoader) ReadFlowStats() (map[FlowKey]uint64, error) {
	stats := make(map[FlowKey]uint64)

	// 遍历流量统计 Map
	var key FlowKey
	var value uint64

	iter := bl.objs.FlowStats.Iterate()
	for iter.Next(&key, &value) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating flow stats: %w", err)
	}

	return stats, nil
}

// Close 关闭加载器
func (bl *Bpf2goLoader) Close() error {
	var lastErr error

	// 关闭所有链接
	for _, l := range bl.links {
		if err := l.Close(); err != nil {
			fmt.Printf("⚠️  Error closing link: %v\n", err)
			lastErr = err
		}
	}

	// 关闭对象
	if err := bl.objs.Close(); err != nil {
		fmt.Printf("⚠️  Error closing objects: %v\n", err)
		lastErr = err
	}

	fmt.Println("🧹 Bpf2go loader closed")
	return lastErr
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

// FormatBytes 格式化字节数
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
