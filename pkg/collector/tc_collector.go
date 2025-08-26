package collector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

// TCDirection TC 流量方向
type TCDirection uint32

const (
	TCDirectionIngress TCDirection = 0
	TCDirectionEgress  TCDirection = 1
)

// String 返回方向的字符串表示
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

// TCStatType TC 统计类型
type TCStatType uint32

const (
	TCStatPackets TCStatType = 0
	TCStatBytes   TCStatType = 1
)

// String 返回统计类型的字符串表示
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

// InterfaceStats 网络接口统计信息
type InterfaceStats struct {
	InterfaceName string
	InterfaceIndex uint32
	
	// 入站统计
	IngressPackets uint64
	IngressBytes   uint64
	
	// 出站统计
	EgressPackets  uint64
	EgressBytes    uint64
	
	// 速率信息 (per second)
	IngressPacketsRate float64
	IngressBytesRate   float64
	EgressPacketsRate  float64
	EgressBytesRate    float64
	
	LastUpdated time.Time
}

// previousStats 存储上一次的统计数据用于计算速率
type previousStats struct {
	packets   uint64
	bytes     uint64
	timestamp time.Time
}

// TCCollector TC 层流量数据收集器
type TCCollector struct {
	manager       *ebpf.Manager
	interfaces    map[uint32]string // ifindex -> interface name
	previousStats map[string]map[TCDirection]*previousStats // ifname -> direction -> stats
	mutex         sync.RWMutex
	collectInterval time.Duration
}

// NewTCCollector 创建新的 TC 收集器
func NewTCCollector(manager *ebpf.Manager) *TCCollector {
	return &TCCollector{
		manager:         manager,
		interfaces:      make(map[uint32]string),
		previousStats:   make(map[string]map[TCDirection]*previousStats),
		collectInterval: 5 * time.Second, // 默认 5 秒收集间隔
	}
}

// SetCollectInterval 设置收集间隔
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
	
	// 清空旧的映射
	tc.interfaces = make(map[uint32]string)
	
	for _, iface := range interfaces {
		tc.interfaces[uint32(iface.Index)] = iface.Name
	}
	
	return nil
}

// getInterfaceName 根据接口索引获取接口名
func (tc *TCCollector) getInterfaceName(ifindex uint32) string {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	
	if name, exists := tc.interfaces[ifindex]; exists {
		return name
	}
	return fmt.Sprintf("if%d", ifindex)
}

// calculateRate 计算速率
func (tc *TCCollector) calculateRate(ifname string, direction TCDirection, currentPackets, currentBytes uint64, currentTime time.Time) (packetsRate, bytesRate float64) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	
	// 初始化接口的统计历史
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

// StartPeriodicCollection 启动周期性收集
func (tc *TCCollector) StartPeriodicCollection() <-chan []InterfaceStats {
	resultChan := make(chan []InterfaceStats, 1)
	
	go func() {
		defer close(resultChan)
		
		ticker := time.NewTicker(tc.collectInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				if stats, err := tc.CollectOnce(); err == nil {
					select {
					case resultChan <- stats:
					default:
						// 如果通道已满，跳过这次发送
					}
				}
			}
		}
	}()
	
	return resultChan
}

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
