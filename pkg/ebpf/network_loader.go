package ebpf

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/your-org/kube-net-probe/ebpf/network"
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

// NetworkLoader 网络监控程序加载器，使用 bpf2go 生成的代码
type NetworkLoader struct {
	objs  network.NetworkMonitorObjects
	links []link.Link
}

// NewNetworkLoader 创建网络加载器
func NewNetworkLoader() *NetworkLoader {
	return &NetworkLoader{}
}

// LoadPrograms 加载 bpf2go 生成的程序
func (nl *NetworkLoader) LoadPrograms() error {
	// 移除内存锁限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// 使用 bpf2go 生成的函数加载程序和 Maps
	if err := network.LoadNetworkMonitorObjects(&nl.objs, nil); err != nil {
		return fmt.Errorf("loading network monitor objects: %w", err)
	}

	fmt.Println("✅ NetworkMonitor objects loaded successfully")
	fmt.Printf("📋 Loaded programs: XDP=%v, TC_Egress=%v, TC_Ingress=%v\n",
		nl.objs.NetworkMonitorXdp != nil,
		nl.objs.NetworkMonitorTcEgress != nil,
		nl.objs.NetworkMonitorTcIngress != nil)
	fmt.Printf("📋 Loaded maps: FlowStats=%v, PacketStats=%v, TcDeviceStats=%v\n",
		nl.objs.FlowStats != nil,
		nl.objs.PacketStats != nil,
		nl.objs.TcDeviceStats != nil)

	return nil
}

// AttachNetworkPrograms 附加网络监控程序到指定接口
func (nl *NetworkLoader) AttachNetworkPrograms(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", interfaceName, err)
	}

	fmt.Printf("🔗 Attaching to interface %s (index: %d)\n", interfaceName, iface.Index)

	// 附加 XDP 程序
	if nl.objs.NetworkMonitorXdp != nil {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   nl.objs.NetworkMonitorXdp,
			Interface: iface.Index,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP to %s: %w", interfaceName, err)
		}
		nl.links = append(nl.links, l)
		fmt.Printf("✅ XDP program attached to %s\n", interfaceName)
	}

	// TC 程序需要手动附加（显示提示信息）
	if nl.objs.NetworkMonitorTcEgress != nil {
		fmt.Printf("💡 TC egress program available (manual setup required):\n")
		fmt.Printf("   sudo tc qdisc add dev %s clsact\n", interfaceName)
		fmt.Printf("   sudo tc filter add dev %s egress bpf object-file network_monitor.o section tc_egress\n", interfaceName)
	}

	if nl.objs.NetworkMonitorTcIngress != nil {
		fmt.Printf("💡 TC ingress program available (manual setup required):\n")
		fmt.Printf("   sudo tc filter add dev %s ingress bpf object-file network_monitor.o section tc_ingress\n", interfaceName)
	}

	return nil
}

// GetStats 获取全局统计信息
func (nl *NetworkLoader) GetStats() (map[string]uint64, error) {
	stats := make(map[string]uint64)

	// 读取包计数统计
	keys := []uint32{0, 1, 2, 3} // STAT_RX_PACKETS, STAT_TX_PACKETS, STAT_RX_BYTES, STAT_TX_BYTES
	names := []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes"}

	for i, key := range keys {
		var value uint64
		if err := nl.objs.PacketStats.Lookup(key, &value); err != nil {
			// 如果 key 不存在，设置为 0
			value = 0
		}
		stats[names[i]] = value
	}

	return stats, nil
}

// ReadGlobalStats 读取全局统计信息
func (nl *NetworkLoader) ReadGlobalStats() (*GlobalStats, error) {
	stats := &GlobalStats{}

	// 读取 RX 包数
	if err := nl.objs.PacketStats.Lookup(uint32(0), &stats.RxPackets); err != nil {
		stats.RxPackets = 0
	}

	// 读取 TX 包数
	if err := nl.objs.PacketStats.Lookup(uint32(1), &stats.TxPackets); err != nil {
		stats.TxPackets = 0
	}

	// 读取 RX 字节数
	if err := nl.objs.PacketStats.Lookup(uint32(2), &stats.RxBytes); err != nil {
		stats.RxBytes = 0
	}

	// 读取 TX 字节数
	if err := nl.objs.PacketStats.Lookup(uint32(3), &stats.TxBytes); err != nil {
		stats.TxBytes = 0
	}

	stats.Timestamp = time.Now()
	return stats, nil
}

// ReadTCDeviceStats 读取 TC 设备统计信息
func (nl *NetworkLoader) ReadTCDeviceStats() (map[TCDeviceKey]uint64, error) {
	stats := make(map[TCDeviceKey]uint64)

	// 遍历 TC 设备统计 Map
	var key TCDeviceKey
	var value uint64

	iter := nl.objs.TcDeviceStats.Iterate()
	for iter.Next(&key, &value) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating TC device stats: %w", err)
	}

	return stats, nil
}

// ReadFlowStats 读取流量统计信息
func (nl *NetworkLoader) ReadFlowStats() (map[FlowKey]uint64, error) {
	stats := make(map[FlowKey]uint64)

	// 遍历流量统计 Map
	var key FlowKey
	var value uint64

	iter := nl.objs.FlowStats.Iterate()
	for iter.Next(&key, &value) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating flow stats: %w", err)
	}

	return stats, nil
}

// GetPacketStatsMap 获取包统计 Map
func (nl *NetworkLoader) GetPacketStatsMap() *network.NetworkMonitorMaps {
	return &nl.objs.NetworkMonitorMaps
}

// GetFlowStatsMap 获取流统计 Map
func (nl *NetworkLoader) GetFlowStatsMap() *network.NetworkMonitorMaps {
	return &nl.objs.NetworkMonitorMaps
}

// GetTcDeviceStatsMap 获取 TC 设备统计 Map
func (nl *NetworkLoader) GetTcDeviceStatsMap() *network.NetworkMonitorMaps {
	return &nl.objs.NetworkMonitorMaps
}

// Close 关闭加载器和所有资源
func (nl *NetworkLoader) Close() error {
	var lastErr error

	// 关闭所有链接
	for _, l := range nl.links {
		if err := l.Close(); err != nil {
			fmt.Printf("⚠️  Error closing link: %v\n", err)
			lastErr = err
		}
	}

	// 关闭对象
	if err := nl.objs.Close(); err != nil {
		fmt.Printf("⚠️  Error closing objects: %v\n", err)
		lastErr = err
	}

	fmt.Println("🧹 Network loader closed")
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
