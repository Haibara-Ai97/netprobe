// Package ebpf 提供基于 cilium/ebpf 的网络监控功能
// 这个包实现了 eBPF 程序的加载、附加和数据收集功能
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FlowKey 流量标识键 - 对应 C 代码中的 struct flow_key
type FlowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]uint8 // padding for alignment
}

// PacketInfo 数据包信息 - 对应 C 代码中的 struct packet_info
type PacketInfo struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Proto      uint8
	PacketSize uint16
	Timestamp  uint64
}

// SecurityEvent 安全事件 - 对应 C 代码中的 struct security_event
type SecurityEvent struct {
	Timestamp   uint64
	EventType   uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Proto       uint8
	Severity    uint32
	Description [64]byte
}

// 统计键定义
const (
	StatRXPackets = iota
	StatTXPackets
	StatRXBytes
	StatTXBytes
)

// 安全事件类型
const (
	SecurityEventSuspiciousConnection = 1
	SecurityEventPortScan             = 2
	SecurityEventDDoSAttempt          = 3
	SecurityEventMaliciousPayload     = 4
)

// NetworkMonitor Go 语言实现的网络监控器
type NetworkMonitor struct {
	// eBPF 程序和 Maps
	xdpProgram *ebpf.Program
	tcProgram  *ebpf.Program

	// Network monitoring maps
	packetStats  *ebpf.Map
	flowStats    *ebpf.Map
	packetEvents *ebpf.Map

	// Security monitoring maps
	connections    *ebpf.Map
	portScans      *ebpf.Map
	securityEvents *ebpf.Map
	securityStats  *ebpf.Map
	securityConfig *ebpf.Map

	// Links
	xdpLink link.Link
	tcLink  link.Link

	// Event readers
	packetReader   *ringbuf.Reader
	securityReader *ringbuf.Reader

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// NewNetworkMonitor 创建网络监控器
func NewNetworkMonitor() (*NetworkMonitor, error) {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// 检查 eBPF 功能支持
	if err := features.HaveProgramType(ebpf.XDP); err != nil {
		return nil, fmt.Errorf("XDP not supported: %w", err)
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())

	nm := &NetworkMonitor{
		ctx:    ctx,
		cancel: cancel,
	}

	// 创建 Maps
	if err := nm.createMaps(); err != nil {
		cancel()
		return nil, fmt.Errorf("creating maps: %w", err)
	}

	// 创建程序
	if err := nm.createPrograms(); err != nil {
		nm.Close()
		return nil, fmt.Errorf("creating programs: %w", err)
	}

	return nm, nil
}

// NewNetworkMonitorFromObjectFile 从对象文件创建网络监控器
func NewNetworkMonitorFromObjectFile(objectPath string) (*NetworkMonitor, error) {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())

	nm := &NetworkMonitor{
		ctx:    ctx,
		cancel: cancel,
	}

	// 从对象文件加载
	if err := nm.loadFromObjectFile(objectPath); err != nil {
		nm.Close()
		return nil, fmt.Errorf("loading from object file: %w", err)
	}

	return nm, nil
}

// loadFromObjectFile 从对象文件加载 eBPF 程序和 Maps
func (nm *NetworkMonitor) loadFromObjectFile(objectPath string) error {
	// 在实际实现中，这里会使用 ebpf.LoadCollectionSpec
	// 从编译好的 .o 文件加载程序和 Maps
	//
	// spec, err := ebpf.LoadCollectionSpec(objectPath)
	// if err != nil {
	//     return fmt.Errorf("loading collection spec: %w", err)
	// }
	//
	// coll, err := ebpf.NewCollection(spec)
	// if err != nil {
	//     return fmt.Errorf("creating collection: %w", err)
	// }
	//
	// 然后从 collection 中获取程序和 Maps

	// 目前为了演示，我们创建基本的结构
	if err := nm.createMaps(); err != nil {
		return fmt.Errorf("creating maps: %w", err)
	}

	if err := nm.createPrograms(); err != nil {
		return fmt.Errorf("creating programs: %w", err)
	}

	return nil
}

// createMaps 创建 eBPF Maps
func (nm *NetworkMonitor) createMaps() error {
	var err error

	// 网络统计 Map (Array)
	nm.packetStats, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4, // uint32
		ValueSize:  8, // uint64
		MaxEntries: 10,
		Name:       "packet_stats",
	})
	if err != nil {
		return fmt.Errorf("creating packet_stats map: %w", err)
	}

	// 流量统计 Map (Hash)
	nm.flowStats, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(FlowKey{})),
		ValueSize:  8, // uint64
		MaxEntries: 10240,
		Name:       "flow_stats",
	})
	if err != nil {
		return fmt.Errorf("creating flow_stats map: %w", err)
	}

	// 数据包事件 Ring Buffer
	nm.packetEvents, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 1 << 24, // 16MB
		Name:       "packet_events",
	})
	if err != nil {
		return fmt.Errorf("creating packet_events map: %w", err)
	}

	// 连接跟踪 Map
	nm.connections, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(FlowKey{})),
		ValueSize:  32, // connection_info struct size
		MaxEntries: 10240,
		Name:       "connections",
	})
	if err != nil {
		return fmt.Errorf("creating connections map: %w", err)
	}

	// 端口扫描检测 Map
	nm.portScans, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,   // src_ip + dst_ip
		ValueSize:  144, // scan_info struct size
		MaxEntries: 1024,
		Name:       "port_scans",
	})
	if err != nil {
		return fmt.Errorf("creating port_scans map: %w", err)
	}

	// 安全事件 Ring Buffer
	nm.securityEvents, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 1 << 20, // 1MB
		Name:       "security_events",
	})
	if err != nil {
		return fmt.Errorf("creating security_events map: %w", err)
	}

	// 安全统计 Map
	nm.securityStats, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 10,
		Name:       "security_stats",
	})
	if err != nil {
		return fmt.Errorf("creating security_stats map: %w", err)
	}

	// 安全配置 Map
	nm.securityConfig, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
		Name:       "security_config",
	})
	if err != nil {
		return fmt.Errorf("creating security_config map: %w", err)
	}

	return nil
}

// createPrograms 创建 eBPF 程序（从预编译的对象文件加载）
func (nm *NetworkMonitor) createPrograms() error {
	// 在实际使用中，我们会从编译好的 .o 文件加载程序
	// 这里为了演示，我们创建简单的占位程序

	// 创建一个简单的 XDP 程序（返回 XDP_PASS）
	xdpSpec := &ebpf.ProgramSpec{
		Type:    ebpf.XDP,
		License: "GPL",
		Name:    "network_monitor_xdp",
	}

	var err error
	nm.xdpProgram, err = ebpf.NewProgram(xdpSpec)
	if err != nil {
		return fmt.Errorf("creating XDP program: %w", err)
	}

	// 创建一个简单的 TC 程序
	tcSpec := &ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "GPL",
		Name:    "network_monitor_tc",
	}

	nm.tcProgram, err = ebpf.NewProgram(tcSpec)
	if err != nil {
		return fmt.Errorf("creating TC program: %w", err)
	}

	return nil
}

// AttachToInterface 附加到网络接口
func (nm *NetworkMonitor) AttachToInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", ifaceName, err)
	}

	// 附加 XDP 程序
	nm.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   nm.xdpProgram,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // 使用通用模式以兼容更多驱动
	})
	if err != nil {
		return fmt.Errorf("attaching XDP program: %w", err)
	}

	return nil
}

// StartEventProcessing 启动事件处理
func (nm *NetworkMonitor) StartEventProcessing() error {
	var err error

	// 创建数据包事件读取器
	nm.packetReader, err = ringbuf.NewReader(nm.packetEvents)
	if err != nil {
		return fmt.Errorf("creating packet event reader: %w", err)
	}

	// 创建安全事件读取器
	nm.securityReader, err = ringbuf.NewReader(nm.securityEvents)
	if err != nil {
		return fmt.Errorf("creating security event reader: %w", err)
	}

	// 启动事件处理协程
	go nm.processPacketEvents()
	go nm.processSecurityEvents()

	return nil
}

// processPacketEvents 处理数据包事件
func (nm *NetworkMonitor) processPacketEvents() {
	for {
		select {
		case <-nm.ctx.Done():
			return
		default:
		}

		record, err := nm.packetReader.Read()
		if err != nil {
			// 检查是否是因为 ringbuf 关闭导致的错误
			if err.Error() == "ringbuf is closed" {
				return
			}
			continue
		}

		// 解析数据包信息
		if len(record.RawSample) < int(unsafe.Sizeof(PacketInfo{})) {
			continue
		}

		var pktInfo PacketInfo
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.LittleEndian, &pktInfo); err != nil {
			continue
		}

		// 处理数据包事件
		nm.handlePacketEvent(&pktInfo)
	}
}

// processSecurityEvents 处理安全事件
func (nm *NetworkMonitor) processSecurityEvents() {
	for {
		select {
		case <-nm.ctx.Done():
			return
		default:
		}

		record, err := nm.securityReader.Read()
		if err != nil {
			// 检查是否是因为 ringbuf 关闭导致的错误
			if err.Error() == "ringbuf is closed" {
				return
			}
			continue
		}

		// 解析安全事件
		if len(record.RawSample) < int(unsafe.Sizeof(SecurityEvent{})) {
			continue
		}

		var secEvent SecurityEvent
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.LittleEndian, &secEvent); err != nil {
			continue
		}

		// 处理安全事件
		nm.handleSecurityEvent(&secEvent)
	}
}

// handlePacketEvent 处理数据包事件
func (nm *NetworkMonitor) handlePacketEvent(pktInfo *PacketInfo) {
	srcIP := intToIP(pktInfo.SrcIP)
	dstIP := intToIP(pktInfo.DstIP)

	fmt.Printf("Packet: %s:%d -> %s:%d, Proto: %d, Size: %d\n",
		srcIP, pktInfo.SrcPort,
		dstIP, pktInfo.DstPort,
		pktInfo.Proto, pktInfo.PacketSize)
}

// handleSecurityEvent 处理安全事件
func (nm *NetworkMonitor) handleSecurityEvent(secEvent *SecurityEvent) {
	srcIP := intToIP(secEvent.SrcIP)
	dstIP := intToIP(secEvent.DstIP)
	description := string(secEvent.Description[:])

	fmt.Printf("Security Event: Type=%d, %s:%d -> %s:%d, Severity=%d, Desc=%s\n",
		secEvent.EventType,
		srcIP, secEvent.SrcPort,
		dstIP, secEvent.DstPort,
		secEvent.Severity, description)
}

// GetPacketStats 获取数据包统计
func (nm *NetworkMonitor) GetPacketStats() (map[string]uint64, error) {
	stats := make(map[string]uint64)

	// 读取 RX 包数量
	var rxPackets uint64
	if err := nm.packetStats.Lookup(uint32(StatRXPackets), &rxPackets); err != nil {
		// 如果键不存在，设置为 0
		rxPackets = 0
	}
	stats["rx_packets"] = rxPackets

	// 读取 TX 包数量
	var txPackets uint64
	if err := nm.packetStats.Lookup(uint32(StatTXPackets), &txPackets); err != nil {
		txPackets = 0
	}
	stats["tx_packets"] = txPackets

	// 读取 RX 字节数
	var rxBytes uint64
	if err := nm.packetStats.Lookup(uint32(StatRXBytes), &rxBytes); err != nil {
		rxBytes = 0
	}
	stats["rx_bytes"] = rxBytes

	// 读取 TX 字节数
	var txBytes uint64
	if err := nm.packetStats.Lookup(uint32(StatTXBytes), &txBytes); err != nil {
		txBytes = 0
	}
	stats["tx_bytes"] = txBytes

	return stats, nil
}

// GetFlowStats 获取流量统计
func (nm *NetworkMonitor) GetFlowStats() (map[string]uint64, error) {
	flows := make(map[string]uint64)

	// 遍历流量统计 Map
	var key FlowKey
	var value uint64

	iter := nm.flowStats.Iterate()
	for iter.Next(&key, &value) {
		flowID := fmt.Sprintf("%s:%d->%s:%d",
			intToIP(key.SrcIP), key.SrcPort,
			intToIP(key.DstIP), key.DstPort)
		flows[flowID] = value
	}

	return flows, iter.Err()
}

// SetSecurityConfig 设置安全配置
func (nm *NetworkMonitor) SetSecurityConfig(key, value uint32) error {
	return nm.securityConfig.Update(key, value, ebpf.UpdateAny)
}

// Close 关闭监控器
func (nm *NetworkMonitor) Close() error {
	// 取消上下文，停止事件处理协程
	if nm.cancel != nil {
		nm.cancel()
	}

	var lastErr error

	if nm.packetReader != nil {
		if err := nm.packetReader.Close(); err != nil {
			lastErr = err
		}
	}

	if nm.securityReader != nil {
		if err := nm.securityReader.Close(); err != nil {
			lastErr = err
		}
	}

	if nm.xdpLink != nil {
		if err := nm.xdpLink.Close(); err != nil {
			lastErr = err
		}
	}

	if nm.tcLink != nil {
		if err := nm.tcLink.Close(); err != nil {
			lastErr = err
		}
	}

	// 关闭程序
	if nm.xdpProgram != nil {
		if err := nm.xdpProgram.Close(); err != nil {
			lastErr = err
		}
	}

	if nm.tcProgram != nil {
		if err := nm.tcProgram.Close(); err != nil {
			lastErr = err
		}
	}

	// 关闭 Maps
	maps := []*ebpf.Map{
		nm.packetStats, nm.flowStats, nm.packetEvents,
		nm.connections, nm.portScans, nm.securityEvents,
		nm.securityStats, nm.securityConfig,
	}

	for _, m := range maps {
		if m != nil {
			if err := m.Close(); err != nil {
				lastErr = err
			}
		}
	}

	return lastErr
}

// intToIP 将整数转换为 IP 地址字符串
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24))
}
