package ebpf

import (
	"context"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Haibara-Ai97/netprobe/ebpf/network"
)

// RingBufferReader Ring Buffer 读取器
type RingBufferReader struct {
	reader           *ringbuf.Reader
	eventChan        chan *NetworkEvent
	batchChan        chan []*NetworkEvent
	handlers         []EventHandler
	
	// 配置
	batchSize        int
	batchTimeout     time.Duration
	
	// 统计
	eventsRead       uint64
	eventsDropped    uint64
	batchesProcessed uint64
	
	// 控制
	ctx              context.Context
	cancel           context.CancelFunc
}

// NetworkLoader 网络监控程序加载器
type NetworkLoader struct {
	objs             network.NetworkMonitorObjects
	links            []link.Link
	
	// Ring Buffer 支持
	ringbufReader    *RingBufferReader
	config          *RingBufferConfig
	
	// XDP程序管理
	currentXDPType   XDPProgramType
	xdpAttached      bool
}

// NewNetworkLoader 创建网络加载器
func NewNetworkLoader() *NetworkLoader {
	return &NetworkLoader{
		config: &RingBufferConfig{
			EnableTCEvents: true,
		},
		currentXDPType: XDPBasicMonitor,
		xdpAttached:    false,
	}
}

// LoadPrograms 加载 eBPF 程序
func (nl *NetworkLoader) LoadPrograms() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock limit: %w", err)
	}

	if err := network.LoadNetworkMonitorObjects(&nl.objs, nil); err != nil {
		return fmt.Errorf("loading network monitor objects: %w", err)
	}

	fmt.Println("✅ Successfully loaded eBPF programs")
	return nl.configureRingBuffer()
}

// SetXDPProgramType 设置XDP程序类型
func (nl *NetworkLoader) SetXDPProgramType(programType XDPProgramType) {
	nl.currentXDPType = programType
}

// SetRingBufferConfig 设置Ring Buffer配置
func (nl *NetworkLoader) SetRingBufferConfig(config *RingBufferConfig) {
	nl.config = config
}

// AttachNetworkPrograms 附加网络程序到接口
func (nl *NetworkLoader) AttachNetworkPrograms(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", interfaceName, err)
	}

	fmt.Printf("🔗 Attaching to interface %s (index: %d)\n", interfaceName, iface.Index)

	// 附加XDP程序
	if err := nl.attachXDPProgram(interfaceName); err != nil {
		return fmt.Errorf("attaching XDP program: %w", err)
	}

	// 附加TC程序
	if err := nl.attachTCPrograms(interfaceName, iface.Index); err != nil {
		fmt.Printf("⚠️  TC program attachment failed: %v\n", err)
	}

	return nil
}

// InitializeRingBufferReader 初始化Ring Buffer读取器
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
		reader:           reader,
		eventChan:        make(chan *NetworkEvent, 1000),
		batchChan:        make(chan []*NetworkEvent, 100),
		handlers:         []EventHandler{},
		batchSize:        100,
		batchTimeout:     100 * time.Millisecond,
		ctx:              childCtx,
		cancel:           cancel,
	}
	
	return nil
}

// StartRingBufferProcessing 启动Ring Buffer处理
func (nl *NetworkLoader) StartRingBufferProcessing() error {
	if nl.ringbufReader == nil {
		return fmt.Errorf("ring buffer reader not initialized")
	}
	
	go nl.ringbufReader.readEvents()
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

// 统计读取方法

// GetStats 获取基础统计
func (nl *NetworkLoader) GetStats() (map[string]uint64, error) {
	stats := make(map[string]uint64)
	keys := []uint32{0, 1, 2, 3}
	names := []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes"}

	for i, key := range keys {
		var value uint64
		if err := nl.objs.PacketStats.Lookup(key, &value); err != nil {
			value = 0
		}
		stats[names[i]] = value
	}

	return stats, nil
}

// ReadGlobalStats 读取全局统计
func (nl *NetworkLoader) ReadGlobalStats() (*GlobalStats, error) {
	stats := &GlobalStats{Timestamp: time.Now()}
	
	nl.objs.PacketStats.Lookup(uint32(0), &stats.RxPackets)
	nl.objs.PacketStats.Lookup(uint32(1), &stats.TxPackets)
	nl.objs.PacketStats.Lookup(uint32(2), &stats.RxBytes)
	nl.objs.PacketStats.Lookup(uint32(3), &stats.TxBytes)
	
	return stats, nil
}

// ReadSecurityStats 读取安全统计
func (nl *NetworkLoader) ReadSecurityStats() (*SecurityStats, error) {
	stats := &SecurityStats{}
	
	nl.objs.PacketStats.Lookup(uint32(11), &stats.DDosBlocked)
	nl.objs.PacketStats.Lookup(uint32(13), &stats.SecurityEvents)
	nl.objs.PacketStats.Lookup(uint32(8), &stats.XDPDropped)
	stats.BlacklistedIPs = nl.countBlacklistedIPs()
	
	return stats, nil
}

// ReadLoadBalancerStats 读取负载均衡统计
func (nl *NetworkLoader) ReadLoadBalancerStats() (*LoadBalancerStats, error) {
	stats := &LoadBalancerStats{
		TargetCounts: make(map[uint32]uint64),
	}
	
	nl.objs.PacketStats.Lookup(uint32(12), &stats.LBDecisions)
	
	var key uint32
	var value uint64
	iter := nl.objs.LbStats.Iterate()
	for iter.Next(&key, &value) {
		stats.TargetCounts[key] = value
	}
	
	return stats, iter.Err()
}

// ReadTCDeviceStats 读取TC设备统计
func (nl *NetworkLoader) ReadTCDeviceStats() (map[TCDeviceKey]uint64, error) {
	stats := make(map[TCDeviceKey]uint64)
	
	var key TCDeviceKey
	var value uint64
	iter := nl.objs.TcDeviceStats.Iterate()
	for iter.Next(&key, &value) {
		stats[key] = value
	}
	
	return stats, iter.Err()
}

// ReadFlowStats 读取流统计
func (nl *NetworkLoader) ReadFlowStats() (map[FlowKey]uint64, error) {
	stats := make(map[FlowKey]uint64)
	
	var key FlowKey
	var value uint64
	iter := nl.objs.FlowStats.Iterate()
	for iter.Next(&key, &value) {
		stats[key] = value
	}
	
	return stats, iter.Err()
}

// 黑名单管理方法

// AddToBlacklist 添加IP到黑名单
func (nl *NetworkLoader) AddToBlacklist(ip string) error {
	ipInt, err := ipStringToUint32(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", ip, err)
	}
	
	now := uint64(time.Now().UnixNano())
	if err := nl.objs.BlacklistMap.Update(ipInt, now, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("adding IP %s to blacklist: %w", ip, err)
	}
	
	fmt.Printf("✅ IP %s added to blacklist\n", ip)
	return nil
}

// RemoveFromBlacklist 从黑名单移除IP
func (nl *NetworkLoader) RemoveFromBlacklist(ip string) error {
	ipInt, err := ipStringToUint32(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", ip, err)
	}
	
	if err := nl.objs.BlacklistMap.Delete(ipInt); err != nil {
		return fmt.Errorf("removing IP %s from blacklist: %w", ip, err)
	}
	
	fmt.Printf("✅ IP %s removed from blacklist\n", ip)
	return nil
}

// GetBlacklistedIPs 获取黑名单IP列表
func (nl *NetworkLoader) GetBlacklistedIPs() ([]string, error) {
	var ips []string
	now := uint64(time.Now().UnixNano())
	
	var key uint32
	var value uint64
	iter := nl.objs.BlacklistMap.Iterate()
	for iter.Next(&key, &value) {
		if now-value <= 60000000000 { // 60秒内有效
			ips = append(ips, ipUint32ToString(key))
		}
	}
	
	return ips, iter.Err()
}

// ClearExpiredBlacklist 清理过期黑名单
func (nl *NetworkLoader) ClearExpiredBlacklist() error {
	now := uint64(time.Now().UnixNano())
	var expiredKeys []uint32
	
	var key uint32
	var value uint64
	iter := nl.objs.BlacklistMap.Iterate()
	for iter.Next(&key, &value) {
		if now-value > 60000000000 { // 超过60秒
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	if err := iter.Err(); err != nil {
		return err
	}
	
	for _, key := range expiredKeys {
		nl.objs.BlacklistMap.Delete(key)
	}
	
	if len(expiredKeys) > 0 {
		fmt.Printf("✅ Cleaned up %d expired blacklist entries\n", len(expiredKeys))
	}
	
	return nil
}

// ResetStatistics 重置所有统计
func (nl *NetworkLoader) ResetStatistics() error {
	// 重置全局统计
	zero := uint64(0)
	for i := uint32(0); i < 16; i++ {
		nl.objs.PacketStats.Update(i, zero, ebpf.UpdateAny)
	}
	
	// 清空其他maps
	nl.clearMap(nl.objs.FlowStats)
	nl.clearMap(nl.objs.TcDeviceStats)
	
	for i := uint32(0); i < 16; i++ {
		nl.objs.LbStats.Update(i, zero, ebpf.UpdateAny)
	}
	
	fmt.Println("✅ All statistics reset")
	return nil
}

// GetRingBufferStats 获取Ring Buffer统计
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

// Close 关闭loader
func (nl *NetworkLoader) Close() error {
	if nl.ringbufReader != nil {
		nl.ringbufReader.cancel()
		if nl.ringbufReader.reader != nil {
			nl.ringbufReader.reader.Close()
		}
	}
	
	for _, l := range nl.links {
		l.Close()
	}
	
	return nl.objs.Close()
}

// 内部方法

func (nl *NetworkLoader) configureRingBuffer() error {
	var configValue uint32 = 0
	if nl.config.EnableXDPEvents {
		configValue |= 1 << 0
	}
	if nl.config.EnableTCEvents {
		configValue |= 1 << 1
	}
	if nl.config.EnableDetailedEvents {
		configValue |= 1 << 2
	}
	
	key := uint32(0)
	if err := nl.objs.RingbufConfig.Update(key, configValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating ringbuf config: %w", err)
	}
	
	fmt.Printf("✅ Ring Buffer configured: XDP=%t, TC=%t, Detailed=%t\n",
		nl.config.EnableXDPEvents, nl.config.EnableTCEvents, nl.config.EnableDetailedEvents)
	
	return nil
}

func (nl *NetworkLoader) attachXDPProgram(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	
	var program *ebpf.Program
	var programName string
	
	switch nl.currentXDPType {
	case XDPBasicMonitor:
		program = nl.objs.NetworkMonitorXdp
		programName = "Basic Monitor"
	case XDPAdvancedFilter:
		program = nl.objs.XdpAdvancedFilter
		programName = "Advanced Filter"
	case XDPLoadBalancer:
		program = nl.objs.XdpLoadBalancer
		programName = "Load Balancer"
	default:
		return fmt.Errorf("unsupported XDP program type: %d", nl.currentXDPType)
	}
	
	if program == nil {
		return fmt.Errorf("XDP program not loaded for type: %s", programName)
	}
	
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP %s to %s: %w", programName, interfaceName, err)
	}
	
	nl.links = append(nl.links, l)
	nl.xdpAttached = true
	fmt.Printf("✅ XDP %s program attached to %s\n", programName, interfaceName)
	
	return nil
}

func (nl *NetworkLoader) attachTCPrograms(interfaceName string, ifindex int) error {
	// 尝试附加TC ingress程序
	if nl.objs.NetworkMonitorTcIngress != nil {
		if err := nl.attachTCProgram(ifindex, "ingress", nl.objs.NetworkMonitorTcIngress); err == nil {
			fmt.Printf("✅ TC ingress program attached to %s\n", interfaceName)
		}
	}
	
	// 尝试附加TC egress程序
	if nl.objs.NetworkMonitorTcEgress != nil {
		if err := nl.attachTCProgram(ifindex, "egress", nl.objs.NetworkMonitorTcEgress); err == nil {
			fmt.Printf("✅ TC egress program attached to %s\n", interfaceName)
		}
	}
	
	return nil
}

func (nl *NetworkLoader) attachTCProgram(ifindex int, direction string, program *ebpf.Program) error {
	var attach ebpf.AttachType
	switch direction {
	case "ingress":
		attach = ebpf.AttachTCXIngress
	case "egress":
		attach = ebpf.AttachTCXEgress
	default:
		return fmt.Errorf("unsupported TC direction: %s", direction)
	}
	
	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Program:   program,
		Attach:    attach,
		Interface: ifindex,
	})
	if err != nil {
		return err
	}
	
	nl.links = append(nl.links, tcxLink)
	return nil
}

func (nl *NetworkLoader) countBlacklistedIPs() uint64 {
	var count uint64 = 0
	now := uint64(time.Now().UnixNano())
	
	var key uint32
	var value uint64
	iter := nl.objs.BlacklistMap.Iterate()
	for iter.Next(&key, &value) {
		if now-value <= 60000000000 {
			count++
		}
	}
	
	return count
}

func (nl *NetworkLoader) clearMap(m *ebpf.Map) {
	iter := m.Iterate()
	var key, value interface{}
	var keys []interface{}
	
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	
	for _, k := range keys {
		m.Delete(k)
	}
}

// Ring Buffer读取器方法

func (rbr *RingBufferReader) readEvents() {
	defer close(rbr.eventChan)
	
	for {
		select {
		case <-rbr.ctx.Done():
			return
		default:
			record, err := rbr.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}
			
			if len(record.RawSample) >= int(unsafe.Sizeof(NetworkEvent{})) {
				event := (*NetworkEvent)(unsafe.Pointer(&record.RawSample[0]))
				rbr.eventsRead++
				
				select {
				case rbr.eventChan <- event:
				case <-rbr.ctx.Done():
					return
				default:
					rbr.eventsDropped++
				}
			}
		}
	}
}

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
			
			if len(batch) >= rbr.batchSize {
				rbr.processBatch(batch)
				batch = batch[:0]
			}
			
		case <-ticker.C:
			if len(batch) > 0 {
				rbr.processBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (rbr *RingBufferReader) processBatch(batch []*NetworkEvent) {
	rbr.batchesProcessed++
	
	select {
	case rbr.batchChan <- batch:
	case <-rbr.ctx.Done():
		return
	default:
	}
	
	for _, handler := range rbr.handlers {
		handler.HandleBatch(batch)
	}
}
