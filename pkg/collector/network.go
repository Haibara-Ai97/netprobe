package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"k8s.io/klog/v2"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

// NetworkCollector 网络数据收集器
type NetworkCollector struct {
	name        string
	ebpfManager *ebpf.Manager
	metrics     *NetworkMetrics
	mu          sync.RWMutex
	stopCh      chan struct{}
}

// NetworkMetrics 网络指标数据结构
type NetworkMetrics struct {
	PacketsRx   uint64            `json:"packets_rx"`
	PacketsTx   uint64            `json:"packets_tx"`
	BytesRx     uint64            `json:"bytes_rx"`
	BytesTx     uint64            `json:"bytes_tx"`
	Connections uint64            `json:"connections"`
	FlowStats   map[string]uint64 `json:"flow_stats"`
	LastUpdated time.Time         `json:"last_updated"`
}

// NewNetworkCollector 创建网络数据收集器
func NewNetworkCollector(ebpfManager *ebpf.Manager) *NetworkCollector {
	return &NetworkCollector{
		name:        "network",
		ebpfManager: ebpfManager,
		metrics: &NetworkMetrics{
			FlowStats: make(map[string]uint64),
		},
		stopCh: make(chan struct{}),
	}
}

// Name 返回收集器名称
func (c *NetworkCollector) Name() string {
	return c.name
}

// Start 启动网络数据收集
func (c *NetworkCollector) Start(ctx context.Context) error {
	klog.InfoS("Starting network collector")

	// 启动数据收集循环
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			if err := c.collectMetrics(); err != nil {
				klog.ErrorS(err, "Failed to collect network metrics")
			}
		}
	}
}

// Stop 停止收集器
func (c *NetworkCollector) Stop() error {
	klog.InfoS("Stopping network collector")
	close(c.stopCh)
	return nil
}

// collectMetrics 收集网络指标
func (c *NetworkCollector) collectMetrics() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 从 eBPF map 中读取统计数据
	if err := c.readPacketStats(); err != nil {
		return fmt.Errorf("failed to read packet stats: %w", err)
	}

	if err := c.readFlowStats(); err != nil {
		return fmt.Errorf("failed to read flow stats: %w", err)
	}

	c.metrics.LastUpdated = time.Now()
	return nil
}

// readPacketStats 读取包统计数据
func (c *NetworkCollector) readPacketStats() error {
	// 获取网络监控程序
	prog, err := c.ebpfManager.GetProgram("network_monitor")
	if err != nil {
		// 如果程序不存在，跳过
		return nil
	}

	// 获取统计 map
	statsMap, err := prog.GetMap("packet_stats")
	if err != nil {
		return err
	}

	// 读取 RX 统计
	var rxKey uint32 = 0
	var rxValue uint64
	if err := statsMap.Lookup(&rxKey, &rxValue); err != nil {
		if err != ebpf.ErrKeyNotExist {
			return err
		}
	}
	c.metrics.PacketsRx = rxValue

	// 读取 TX 统计
	var txKey uint32 = 1
	var txValue uint64
	if err := statsMap.Lookup(&txKey, &txValue); err != nil {
		if err != ebpf.ErrKeyNotExist {
			return err
		}
	}
	c.metrics.PacketsTx = txValue

	return nil
}

// readFlowStats 读取流量统计数据
func (c *NetworkCollector) readFlowStats() error {
	// 获取网络监控程序
	prog, err := c.ebpfManager.GetProgram("network_monitor")
	if err != nil {
		return nil
	}

	// 获取流量 map
	flowMap, err := prog.GetMap("flow_stats")
	if err != nil {
		return err
	}

	// 遍历所有流量条目
	var key, nextKey FlowKey
	var value uint64

	iterator := flowMap.Iterate()
	for iterator.Next(&key, &value) {
		flowID := fmt.Sprintf("%s:%d->%s:%d",
			intToIP(key.SrcIP), key.SrcPort,
			intToIP(key.DstIP), key.DstPort)
		c.metrics.FlowStats[flowID] = value
	}

	return iterator.Err()
}

// GetMetrics 获取网络指标
func (c *NetworkCollector) GetMetrics() (map[string]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"packets_rx":   c.metrics.PacketsRx,
		"packets_tx":   c.metrics.PacketsTx,
		"bytes_rx":     c.metrics.BytesRx,
		"bytes_tx":     c.metrics.BytesTx,
		"connections":  c.metrics.Connections,
		"flow_stats":   c.metrics.FlowStats,
		"last_updated": c.metrics.LastUpdated,
	}, nil
}

// FlowKey 流量键结构
type FlowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]uint8 // padding
}

// intToIP 将整数转换为 IP 地址字符串
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24))
}
