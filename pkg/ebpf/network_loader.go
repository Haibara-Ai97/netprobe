package ebpf

import (
	"context"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/Haibara-Ai97/netprobe/ebpf/network"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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

// RingBufferConfig Ring Buffer 配置
type RingBufferConfig struct {
	EnableXDPEvents     bool // 启用 XDP 事件
	EnableTCEvents      bool // 启用 TC 事件  
	EnableDetailedEvents bool // 启用详细事件
}

// EventHandler 事件处理器接口
type EventHandler interface {
	HandleEvent(event *NetworkEvent) error
	HandleBatch(events []*NetworkEvent) error
}

// RingBufferReader Ring Buffer 读取器
type RingBufferReader struct {
	reader      *ringbuf.Reader
	eventChan   chan *NetworkEvent
	batchChan   chan []*NetworkEvent
	handlers    []EventHandler
	
	// 配置
	batchSize    int
	batchTimeout time.Duration
	bufferSize   int
	
	// 统计
	eventsRead   uint64
	eventsDropped uint64
	batchesProcessed uint64
	
	// 控制
	ctx    context.Context
	cancel context.CancelFunc
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
	objs          network.NetworkMonitorObjects
	links         []link.Link
	
	// Ring Buffer 支持
	ringbufReader *RingBufferReader
	config        *RingBufferConfig
}

// NewNetworkLoader 创建网络加载器
func NewNetworkLoader() *NetworkLoader {
	return &NetworkLoader{
		config: &RingBufferConfig{
			EnableTCEvents: true, // 默认启用 TC 事件，避免重复
		},
	}
}

// LoadPrograms 加载 bpf2go 生成的程序
func (nl *NetworkLoader) LoadPrograms() error {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock limit: %w", err)
	}

	// 加载 eBPF 程序和映射
	if err := network.LoadNetworkMonitorObjects(&nl.objs, nil); err != nil {
		return fmt.Errorf("loading network monitor objects: %w", err)
	}

	fmt.Println("✅ Successfully loaded eBPF programs")
	
	// 配置 Ring Buffer
	if err := nl.configureRingBuffer(); err != nil {
		return fmt.Errorf("configuring ring buffer: %w", err)
	}
	
	return nil
}

// configureRingBuffer 配置 Ring Buffer 设置
func (nl *NetworkLoader) configureRingBuffer() error {
	// 设置配置值
	var configValue uint32 = 0
	if nl.config.EnableXDPEvents {
		configValue |= 1 << 0 // CONFIG_ENABLE_XDP_EVENTS
	}
	if nl.config.EnableTCEvents {
		configValue |= 1 << 1 // CONFIG_ENABLE_TC_EVENTS
	}
	if nl.config.EnableDetailedEvents {
		configValue |= 1 << 2 // CONFIG_ENABLE_DETAILED_EVENTS
	}
	
	// 更新配置映射
	key := uint32(0)
	if err := nl.objs.RingbufConfig.Update(key, configValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating ringbuf config: %w", err)
	}
	
	fmt.Printf("✅ Ring Buffer configured: XDP=%t, TC=%t, Detailed=%t\n",
		nl.config.EnableXDPEvents, nl.config.EnableTCEvents, nl.config.EnableDetailedEvents)
	
	return nil
}

// InitializeRingBufferReader 初始化 Ring Buffer 读取器
func (nl *NetworkLoader) InitializeRingBufferReader(ctx context.Context) error {
	if nl.objs.Events == nil {
		return fmt.Errorf("events map not available")
	}
	
	reader, err := ringbuf.NewReader(nl.objs.Events)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	
	childCtx, cancel := context.WithCancel(ctx)
	
	nl.ringbufReader = &RingBufferReader{
		reader:       reader,
		eventChan:    make(chan *NetworkEvent, 1000),
		batchChan:    make(chan []*NetworkEvent, 100),
		handlers:     []EventHandler{},
		batchSize:    100,
		batchTimeout: 100 * time.Millisecond,
		bufferSize:   1000,
		ctx:          childCtx,
		cancel:       cancel,
	}
	
	return nil
}

// StartRingBufferProcessing 启动 Ring Buffer 事件处理
func (nl *NetworkLoader) StartRingBufferProcessing() error {
	if nl.ringbufReader == nil {
		return fmt.Errorf("ring buffer reader not initialized")
	}
	
	// 启动事件读取协程
	go nl.ringbufReader.readEvents()
	
	// 启动批处理协程
	go nl.ringbufReader.batchProcessor()
	
	fmt.Println("✅ Ring Buffer processing started")
	return nil
}

// AddEventHandler 添加事件处理器
func (nl *NetworkLoader) AddEventHandler(handler EventHandler) {
	if nl.ringbufReader != nil {
		nl.ringbufReader.handlers = append(nl.ringbufReader.handlers, handler)
	}
}

// GetEventChannel 获取事件通道（用于自定义处理）
func (nl *NetworkLoader) GetEventChannel() <-chan *NetworkEvent {
	if nl.ringbufReader != nil {
		return nl.ringbufReader.eventChan
	}
	return nil
}

// GetBatchChannel 获取批量事件通道
func (nl *NetworkLoader) GetBatchChannel() <-chan []*NetworkEvent {
	if nl.ringbufReader != nil {
		return nl.ringbufReader.batchChan
	}
	return nil
}

// SetRingBufferConfig 设置 Ring Buffer 配置
func (nl *NetworkLoader) SetRingBufferConfig(config *RingBufferConfig) {
	nl.config = config
}

// readEvents Ring Buffer 事件读取循环
func (rbr *RingBufferReader) readEvents() {
	defer close(rbr.eventChan)
	
	for {
		select {
		case <-rbr.ctx.Done():
			return
		default:
			// 从 Ring Buffer 读取事件
			record, err := rbr.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}
			
			// 解析事件（零拷贝）
			if len(record.RawSample) >= int(unsafe.Sizeof(NetworkEvent{})) {
				event := (*NetworkEvent)(unsafe.Pointer(&record.RawSample[0]))
				rbr.eventsRead++
				
				select {
				case rbr.eventChan <- event:
				case <-rbr.ctx.Done():
					return
				default:
					// 缓冲区满，丢弃事件
					rbr.eventsDropped++
				}
			}
		}
	}
}

// batchProcessor 批量事件处理器
func (rbr *RingBufferReader) batchProcessor() {
	defer close(rbr.batchChan)
	
	ticker := time.NewTicker(rbr.batchTimeout)
	defer ticker.Stop()
	
	batch := make([]*NetworkEvent, 0, rbr.batchSize)
	
	for {
		select {
		case <-rbr.ctx.Done():
			if len(batch) > 0 {
				rbr.processBatch(batch)
			}
			return
			
		case event := <-rbr.eventChan:
			batch = append(batch, event)
			
			// 批次满了
			if len(batch) >= rbr.batchSize {
				rbr.processBatch(batch)
				batch = batch[:0] // 重置切片
			}
			
		case <-ticker.C:
			// 超时，处理当前批次
			if len(batch) > 0 {
				rbr.processBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatch 处理事件批次
func (rbr *RingBufferReader) processBatch(batch []*NetworkEvent) {
	rbr.batchesProcessed++
	
	// 发送到批量通道
	select {
	case rbr.batchChan <- batch:
	case <-rbr.ctx.Done():
		return
	default:
		// 非阻塞
	}
	
	// 调用注册的处理器
	for _, handler := range rbr.handlers {
		if err := handler.HandleBatch(batch); err != nil {
			// 记录错误，但继续处理
			fmt.Printf("Handler error: %v\n", err)
		}
	}
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

	// 检测并附加 TC 程序
	if nl.objs.NetworkMonitorTcIngress != nil || nl.objs.NetworkMonitorTcEgress != nil {
		err = nl.attachTCPrograms(interfaceName, iface.Index)
		if err != nil {
			fmt.Printf("⚠️  TC program attachment failed: %v\n", err)
			fmt.Printf("💡 To enable TC monitoring, run:\n")
			fmt.Printf("   sudo tc qdisc add dev %s clsact\n", interfaceName)
		}
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

	// 检查 TC 设备统计 Map 是否已初始化
	if nl.objs.TcDeviceStats == nil {
		return nil, fmt.Errorf("TC device stats map is not initialized - call LoadPrograms() first")
	}

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
func (nl *NetworkLoader) GetPacketStatsMap() *ebpf.Map {
	return nl.objs.PacketStats
}

// GetFlowStatsMap 获取流统计 Map
func (nl *NetworkLoader) GetFlowStatsMap() *ebpf.Map {
	return nl.objs.FlowStats
}

// GetTcDeviceStatsMap 获取 TC 设备统计 Map
func (nl *NetworkLoader) GetTcDeviceStatsMap() *ebpf.Map {
	return nl.objs.TcDeviceStats
}

// Close 关闭加载器和所有资源
func (nl *NetworkLoader) Close() error {
	var lastErr error

	// 停止 Ring Buffer 读取
	if nl.ringbufReader != nil {
		nl.ringbufReader.cancel()
		if nl.ringbufReader.reader != nil {
			if err := nl.ringbufReader.reader.Close(); err != nil {
				fmt.Printf("⚠️  Error closing ring buffer reader: %v\n", err)
				lastErr = err
			}
		}
	}

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

	return lastErr
}

// GetRingBufferStats 获取 Ring Buffer 统计信息
func (nl *NetworkLoader) GetRingBufferStats() map[string]uint64 {
	if nl.ringbufReader == nil {
		return nil
	}
	
	return map[string]uint64{
		"events_read":       nl.ringbufReader.eventsRead,
		"events_dropped":    nl.ringbufReader.eventsDropped,
		"batches_processed": nl.ringbufReader.batchesProcessed,
	}
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

// attachTCPrograms 检测并附加 TC 程序
func (nl *NetworkLoader) attachTCPrograms(interfaceName string, ifindex int) error {
	// 尝试附加 TC ingress 程序
	if nl.objs.NetworkMonitorTcIngress != nil {
		err := nl.attachTCProgram(interfaceName, ifindex, "ingress", nl.objs.NetworkMonitorTcIngress)
		if err != nil {
			fmt.Printf("⚠️  TC ingress attachment failed: %v\n", err)
		} else {
			fmt.Printf("✅ TC ingress program attached to %s\n", interfaceName)
		}
	}

	// 尝试附加 TC egress 程序
	if nl.objs.NetworkMonitorTcEgress != nil {
		err := nl.attachTCProgram(interfaceName, ifindex, "egress", nl.objs.NetworkMonitorTcEgress)
		if err != nil {
			fmt.Printf("⚠️  TC egress attachment failed: %v\n", err)
		} else {
			fmt.Printf("✅ TC egress program attached to %s\n", interfaceName)
		}
	}

	return nil
}

// attachTCProgram 附加单个 TC 程序
func (nl *NetworkLoader) attachTCProgram(interfaceName string, ifindex int, direction string, program *ebpf.Program) error {
	// 确定 TC 附加点
	var attach ebpf.AttachType
	switch direction {
	case "ingress":
		attach = ebpf.AttachTCXIngress
	case "egress":
		attach = ebpf.AttachTCXEgress
	default:
		return fmt.Errorf("unsupported TC direction: %s", direction)
	}

	// 使用 TCX (tc-bpf express) 附加方式
	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Program:   program,
		Attach:    attach,
		Interface: ifindex,
	})
	if err != nil {
		return fmt.Errorf("TC %s attachment failed: %w", direction, err)
	}

	// 保存链接用于后续清理
	nl.links = append(nl.links, tcxLink)
	fmt.Printf("✅ TC %s program attached to %s using TCX\n", direction, interfaceName)
	return nil
}
