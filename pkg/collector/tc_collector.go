package collector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Haibara-Ai97/netprobe/pkg/ebpf"
)

// TCDirection represents the traffic direction in TC layer monitoring
type TCDirection uint32

const (
	TCDirectionIngress TCDirection = 0 // Incoming traffic
	TCDirectionEgress  TCDirection = 1 // Outgoing traffic
)

// String returns human-readable direction name
func (d TCDirection) String() string {
	switch d {
	case TCDirectionIngress:
		return "ingress"
	case TCDirectionEgress:
		return "egress"
	default:
		return "unknown"
	}
}

// TCStatType represents the type of traffic statistics
type TCStatType uint32

const (
	TCStatPackets TCStatType = 0 // Packet count statistics
	TCStatBytes   TCStatType = 1 // Byte count statistics
)

// String returns human-readable statistics type name
func (t TCStatType) String() string {
	switch t {
	case TCStatPackets:
		return "packets"
	case TCStatBytes:
		return "bytes"
	default:
		return "unknown"
	}
}

// InterfaceStats contains comprehensive network interface statistics
// Includes both raw counters and calculated rates for monitoring
type InterfaceStats struct {
	InterfaceName  string // Network interface name (e.g., eth0, wlan0)
	InterfaceIndex uint32 // Kernel interface index

	// Raw packet and byte counters for ingress traffic
	IngressPackets uint64
	IngressBytes   uint64

	// Raw packet and byte counters for egress traffic
	EgressPackets uint64
	EgressBytes   uint64

	// Calculated rates per second for real-time monitoring
	IngressPacketsRate float64 // Packets per second (ingress)
	IngressBytesRate   float64 // Bytes per second (ingress)
	EgressPacketsRate  float64 // Packets per second (egress)
	EgressBytesRate    float64 // Bytes per second (egress)

	LastUpdated time.Time // Timestamp of last statistics update
}

// previousStats stores historical data for rate calculation
type previousStats struct {
	packets   uint64    // Previous packet count
	bytes     uint64    // Previous byte count
	timestamp time.Time // Timestamp of previous measurement
}

// TCCollector implements Traffic Control layer data collection
// Reads statistics from eBPF maps and calculates network rates
type TCCollector struct {
	manager         *ebpf.SimpleEBPFManager                             // eBPF program manager
	interfaces      map[uint32]string                         // Interface index to name mapping
	previousStats   map[string]map[TCDirection]*previousStats // Historical data for rate calculation
	mutex           sync.RWMutex                              // Thread-safe access protection
	collectInterval time.Duration                             // Data collection frequency
}

// NewTCCollector creates a new Traffic Control layer collector
// Initializes data structures for interface monitoring and rate calculation
func NewTCCollector(manager *ebpf.SimpleEBPFManager) *TCCollector {
	return &TCCollector{
		manager:         manager,
		interfaces:      make(map[uint32]string),
		previousStats:   make(map[string]map[TCDirection]*previousStats),
		collectInterval: 5 * time.Second, // Default collection interval
	}
}

// SetCollectInterval configures the data collection frequency
// Lower intervals provide more granular rate calculations but use more CPU
func (tc *TCCollector) SetCollectInterval(interval time.Duration) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.collectInterval = interval
}

// updateInterfaceMapping 更新接口索引到接口名的映射
func (tc *TCCollector) updateInterfaceMapping() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	// Clear previous interface mappings to ensure fresh state
	tc.interfaces = make(map[uint32]string)

	// Build interface index to name mapping for efficient lookups
	for _, iface := range interfaces {
		tc.interfaces[uint32(iface.Index)] = iface.Name
	}

	return nil
}

// getInterfaceName retrieves interface name by kernel index
// Returns a fallback name if interface is not found in mapping
func (tc *TCCollector) getInterfaceName(ifindex uint32) string {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	if name, exists := tc.interfaces[ifindex]; exists {
		return name
	}
	// Fallback to generic interface name if not found
	return fmt.Sprintf("if%d", ifindex)
}

// calculateRate computes per-second rates for packets and bytes
// Uses previous measurements to calculate instantaneous rates
func (tc *TCCollector) calculateRate(ifname string, direction TCDirection, currentPackets,
	currentBytes uint64, currentTime time.Time) (packetsRate, bytesRate float64) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	// Initialize per-interface statistics tracking if needed
	if tc.previousStats[ifname] == nil {
		tc.previousStats[ifname] = make(map[TCDirection]*previousStats)
	}

	prevStats := tc.previousStats[ifname][direction]
	if prevStats == nil {
		// 第一次收集，无法计算速率
		tc.previousStats[ifname][direction] = &previousStats{
			packets:   currentPackets,
			bytes:     currentBytes,
			timestamp: currentTime,
		}
		return 0, 0
	}

	// 计算时间差
	timeDiff := currentTime.Sub(prevStats.timestamp).Seconds()
	if timeDiff <= 0 {
		return 0, 0
	}

	// 计算增量
	packetsDiff := int64(currentPackets - prevStats.packets)
	bytesDiff := int64(currentBytes - prevStats.bytes)

	// 处理计数器重置的情况（假设重置时值变小）
	if packetsDiff < 0 {
		packetsDiff = int64(currentPackets)
	}
	if bytesDiff < 0 {
		bytesDiff = int64(currentBytes)
	}

	// 计算速率
	packetsRate = float64(packetsDiff) / timeDiff
	bytesRate = float64(bytesDiff) / timeDiff

	// 更新历史数据
	tc.previousStats[ifname][direction] = &previousStats{
		packets:   currentPackets,
		bytes:     currentBytes,
		timestamp: currentTime,
	}

	return packetsRate, bytesRate
}

// CollectOnce 执行一次数据收集
func (tc *TCCollector) CollectOnce() ([]InterfaceStats, error) {
	// 更新接口映射
	if err := tc.updateInterfaceMapping(); err != nil {
		return nil, fmt.Errorf("failed to update interface mapping: %w", err)
	}

	// 获取网络加载器
	networkLoader := tc.manager.GetNetworkLoader()
	if networkLoader == nil {
		return nil, fmt.Errorf("network loader is not initialized")
	}

	// 读取 TC 设备统计
	tcStats, err := networkLoader.ReadTCDeviceStats()
	if err != nil {
		return nil, fmt.Errorf("failed to read TC device stats: %w", err)
	}

	// 按接口组织数据
	interfaceData := make(map[uint32]*InterfaceStats)
	currentTime := time.Now()

	for tcKey, value := range tcStats {
		ifindex := tcKey.Ifindex
		direction := TCDirection(tcKey.Direction)
		statType := TCStatType(tcKey.StatType)

		// 获取或创建接口统计
		if interfaceData[ifindex] == nil {
			interfaceData[ifindex] = &InterfaceStats{
				InterfaceName:  tc.getInterfaceName(ifindex),
				InterfaceIndex: ifindex,
				LastUpdated:    currentTime,
			}
		}

		stats := interfaceData[ifindex]

		// 根据方向和统计类型设置数据
		switch direction {
		case TCDirectionIngress:
			switch statType {
			case TCStatPackets:
				stats.IngressPackets = value
			case TCStatBytes:
				stats.IngressBytes = value
			}
		case TCDirectionEgress:
			switch statType {
			case TCStatPackets:
				stats.EgressPackets = value
			case TCStatBytes:
				stats.EgressBytes = value
			}
		}
	}

	// 计算速率并生成结果
	var result []InterfaceStats
	for _, stats := range interfaceData {
		// 计算入站速率
		stats.IngressPacketsRate, stats.IngressBytesRate = tc.calculateRate(
			stats.InterfaceName, TCDirectionIngress,
			stats.IngressPackets, stats.IngressBytes, currentTime)

		// 计算出站速率
		stats.EgressPacketsRate, stats.EgressBytesRate = tc.calculateRate(
			stats.InterfaceName, TCDirectionEgress,
			stats.EgressPackets, stats.EgressBytes, currentTime)

		result = append(result, *stats)
	}

	return result, nil
}

//// StartPeriodicCollection 启动周期性收集
//func (tc *TCCollector) StartPeriodicCollection() <-chan []InterfaceStats {
//	resultChan := make(chan []InterfaceStats, 1)
//
//	go func() {
//		defer close(resultChan)
//
//		ticker := time.NewTicker(tc.collectInterval)
//		defer ticker.Stop()
//
//		for {
//			select {
//			case <-ticker.C:
//				if stats, err := tc.CollectOnce(); err == nil {
//					select {
//					case resultChan <- stats:
//					default:
//						// 如果通道已满，跳过这次发送
//					}
//				}
//			}
//		}
//	}()
//
//	return resultChan
//}

// GetInterfaceCount 获取当前监控的接口数量
func (tc *TCCollector) GetInterfaceCount() int {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return len(tc.interfaces)
}

// GetSupportedInterfaces 获取所有支持的接口列表
func (tc *TCCollector) GetSupportedInterfaces() []string {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	var interfaces []string
	for _, name := range tc.interfaces {
		interfaces = append(interfaces, name)
	}
	return interfaces
}
