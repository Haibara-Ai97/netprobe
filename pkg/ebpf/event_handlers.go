package ebpf

import (
	"log"
	"time"
)

package ebpf

import (
	"fmt"
	"log"
	"net"
	"time"
)

// SecurityEventHandler 安全事件处理器
type SecurityEventHandler struct {
	alertCallback    func(event *NetworkEvent)
	anomalyThreshold int
	anomalyCount     map[uint32]int // IP -> count
	lastCleanup      time.Time
}

// NewSecurityEventHandler 创建安全事件处理器
func NewSecurityEventHandler() *SecurityEventHandler {
	return &SecurityEventHandler{
		anomalyThreshold: 10, // 10次异常后触发告警
		anomalyCount:     make(map[uint32]int),
		lastCleanup:      time.Now(),
	}
}

// SetAlertCallback 设置告警回调函数
func (seh *SecurityEventHandler) SetAlertCallback(callback func(event *NetworkEvent)) {
	seh.alertCallback = callback
}

// HandleEvent 处理单个事件
func (seh *SecurityEventHandler) HandleEvent(event *NetworkEvent) error {
	switch event.EventType {
	case EventTypeSecurity:
		seh.handleSecurityEvent(event)
	case EventTypeDDoS:
		seh.handleDDoSEvent(event)
	case EventTypeAnomaly:
		seh.handleAnomalyEvent(event)
	}
	
	// 定期清理计数器
	if time.Since(seh.lastCleanup) > 5*time.Minute {
		seh.cleanupCounters()
		seh.lastCleanup = time.Now()
	}
	
	return nil
}

// HandleBatch 处理批量事件
func (seh *SecurityEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		seh.HandleEvent(event)
	}
	return nil
}

// 内部方法
func (seh *SecurityEventHandler) handleSecurityEvent(event *NetworkEvent) {
	srcIP := ipUint32ToString(event.SrcIP)
	log.Printf("🚨 SECURITY ALERT: Suspicious packet from %s (size: %d bytes)", 
		srcIP, event.PacketLen)
	
	if seh.alertCallback != nil {
		seh.alertCallback(event)
	}
}

func (seh *SecurityEventHandler) handleDDoSEvent(event *NetworkEvent) {
	srcIP := ipUint32ToString(event.SrcIP)
	log.Printf("🛡️  DDoS DETECTED: Rate limit exceeded from %s, packet blocked", srcIP)
	
	if seh.alertCallback != nil {
		seh.alertCallback(event)
	}
}

func (seh *SecurityEventHandler) handleAnomalyEvent(event *NetworkEvent) {
	seh.anomalyCount[event.SrcIP]++
	
	if seh.anomalyCount[event.SrcIP] >= seh.anomalyThreshold {
		srcIP := ipUint32ToString(event.SrcIP)
		log.Printf("⚠️  ANOMALY THRESHOLD EXCEEDED: %s has %d anomalies", 
			srcIP, seh.anomalyCount[event.SrcIP])
		
		if seh.alertCallback != nil {
			seh.alertCallback(event)
		}
		
		// 重置计数器
		seh.anomalyCount[event.SrcIP] = 0
	}
}

func (seh *SecurityEventHandler) cleanupCounters() {
	for ip := range seh.anomalyCount {
		delete(seh.anomalyCount, ip)
	}
}

// LoadBalancerEventHandler 负载均衡事件处理器
type LoadBalancerEventHandler struct {
	decisions      map[uint32]uint64 // target_if -> count
	totalDecisions uint64
}

// NewLoadBalancerEventHandler 创建负载均衡事件处理器
func NewLoadBalancerEventHandler() *LoadBalancerEventHandler {
	return &LoadBalancerEventHandler{
		decisions: make(map[uint32]uint64),
	}
}

// HandleEvent 处理单个事件
func (lbeh *LoadBalancerEventHandler) HandleEvent(event *NetworkEvent) error {
	if event.EventType == EventTypeLoadBalance {
		lbeh.decisions[event.Ifindex]++
		lbeh.totalDecisions++
		
		if lbeh.totalDecisions%1000 == 0 {
			log.Printf("📊 Load Balancer: %d decisions made", lbeh.totalDecisions)
			lbeh.printDistribution()
		}
	}
	return nil
}

// HandleBatch 处理批量事件
func (lbeh *LoadBalancerEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		lbeh.HandleEvent(event)
	}
	return nil
}

// GetStats 获取负载均衡统计
func (lbeh *LoadBalancerEventHandler) GetStats() map[uint32]uint64 {
	stats := make(map[uint32]uint64)
	for k, v := range lbeh.decisions {
		stats[k] = v
	}
	return stats
}

func (lbeh *LoadBalancerEventHandler) printDistribution() {
	log.Println("Load Distribution:")
	for target, count := range lbeh.decisions {
		percentage := float64(count) / float64(lbeh.totalDecisions) * 100
		log.Printf("  Target %d: %d packets (%.1f%%)", target, count, percentage)
	}
}

// StatisticsEventHandler 统计事件处理器
type StatisticsEventHandler struct {
	packetCount    uint64
	byteCount      uint64
	protocolStats  map[uint8]uint64
	portStats      map[uint16]uint64
	lastReport     time.Time
	reportInterval time.Duration
}

// NewStatisticsEventHandler 创建统计事件处理器
func NewStatisticsEventHandler() *StatisticsEventHandler {
	return &StatisticsEventHandler{
		protocolStats:  make(map[uint8]uint64),
		portStats:      make(map[uint16]uint64),
		lastReport:     time.Now(),
		reportInterval: 30 * time.Second,
	}
}

// HandleEvent 处理单个事件
func (seh *StatisticsEventHandler) HandleEvent(event *NetworkEvent) error {
	seh.packetCount++
	seh.byteCount += uint64(event.PacketLen)
	seh.protocolStats[event.Protocol]++
	
	// 统计目标端口
	if event.DstPort != 0 {
		seh.portStats[event.DstPort]++
	}
	
	// 定期报告统计信息
	if time.Since(seh.lastReport) >= seh.reportInterval {
		seh.reportStatistics()
		seh.lastReport = time.Now()
	}
	
	return nil
}

// HandleBatch 处理批量事件
func (seh *StatisticsEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		seh.HandleEvent(event)
	}
	return nil
}

// GetPacketCount 获取数据包计数
func (seh *StatisticsEventHandler) GetPacketCount() uint64 {
	return seh.packetCount
}

// GetByteCount 获取字节计数
func (seh *StatisticsEventHandler) GetByteCount() uint64 {
	return seh.byteCount
}

// GetProtocolStats 获取协议统计
func (seh *StatisticsEventHandler) GetProtocolStats() map[uint8]uint64 {
	stats := make(map[uint8]uint64)
	for k, v := range seh.protocolStats {
		stats[k] = v
	}
	return stats
}

func (seh *StatisticsEventHandler) reportStatistics() {
	log.Printf("📈 Statistics Report:")
	log.Printf("  Total Packets: %d", seh.packetCount)
	log.Printf("  Total Bytes: %s", formatBytes(seh.byteCount))
	
	// 协议分布
	log.Printf("  Protocol Distribution:")
	for proto, count := range seh.protocolStats {
		percentage := float64(count) / float64(seh.packetCount) * 100
		log.Printf("    %s: %d (%.1f%%)", getProtocolName(proto), count, percentage)
	}
}

// CompositeEventHandler 复合事件处理器，可组合多个处理器
type CompositeEventHandler struct {
	handlers []EventHandler
}

// NewCompositeEventHandler 创建复合事件处理器
func NewCompositeEventHandler() *CompositeEventHandler {
	return &CompositeEventHandler{
		handlers: make([]EventHandler, 0),
	}
}

// AddHandler 添加事件处理器
func (ceh *CompositeEventHandler) AddHandler(handler EventHandler) {
	ceh.handlers = append(ceh.handlers, handler)
}

// HandleEvent 处理单个事件
func (ceh *CompositeEventHandler) HandleEvent(event *NetworkEvent) error {
	for _, handler := range ceh.handlers {
		if err := handler.HandleEvent(event); err != nil {
			log.Printf("Handler error: %v", err)
		}
	}
	return nil
}

// HandleBatch 处理批量事件
func (ceh *CompositeEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, handler := range ceh.handlers {
		if err := handler.HandleBatch(events); err != nil {
			log.Printf("Batch handler error: %v", err)
		}
	}
	return nil
}

// 辅助函数
func ipUint32ToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, ip>>24)
}

func ipStringToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address")
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24, nil
}

// SecurityEventHandler 安全事件处理器
type SecurityEventHandler struct {
	alertCallback    func(event *NetworkEvent)
	anomalyThreshold int
	anomalyCount     map[uint32]int // IP -> count
	lastCleanup      time.Time
}

// NewSecurityEventHandler 创建安全事件处理器
func NewSecurityEventHandler() *SecurityEventHandler {
	return &SecurityEventHandler{
		anomalyThreshold: 10, // 10次异常后触发告警
		anomalyCount:     make(map[uint32]int),
		lastCleanup:      time.Now(),
	}
}

// SetAlertCallback 设置告警回调函数
func (seh *SecurityEventHandler) SetAlertCallback(callback func(event *NetworkEvent)) {
	seh.alertCallback = callback
}

// HandleEvent 处理单个事件
func (seh *SecurityEventHandler) HandleEvent(event *NetworkEvent) error {
	switch event.EventType {
	case EventTypeSecurity:
		seh.handleSecurityEvent(event)
	case EventTypeDDoS:
		seh.handleDDoSEvent(event)
	case EventTypeAnomaly:
		seh.handleAnomalyEvent(event)
	}

	// 定期清理计数器
	if time.Since(seh.lastCleanup) > 5*time.Minute {
		seh.cleanupCounters()
		seh.lastCleanup = time.Now()
	}

	return nil
}

// HandleBatch 处理批量事件
func (seh *SecurityEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		seh.HandleEvent(event)
	}
	return nil
}

// handleSecurityEvent 处理安全事件
func (seh *SecurityEventHandler) handleSecurityEvent(event *NetworkEvent) {
	srcIP := uint32ToIPString(event.SrcIP)
	log.Printf("🚨 SECURITY ALERT: Suspicious packet from %s (size: %d bytes)",
		srcIP, event.PacketLen)

	if seh.alertCallback != nil {
		seh.alertCallback(event)
	}
}

// handleDDoSEvent 处理DDoS事件
func (seh *SecurityEventHandler) handleDDoSEvent(event *NetworkEvent) {
	srcIP := uint32ToIPString(event.SrcIP)
	log.Printf("🛡️  DDoS DETECTED: Rate limit exceeded from %s, packet blocked", srcIP)

	if seh.alertCallback != nil {
		seh.alertCallback(event)
	}
}

// handleAnomalyEvent 处理异常事件
func (seh *SecurityEventHandler) handleAnomalyEvent(event *NetworkEvent) {
	seh.anomalyCount[event.SrcIP]++

	if seh.anomalyCount[event.SrcIP] >= seh.anomalyThreshold {
		srcIP := uint32ToIPString(event.SrcIP)
		log.Printf("⚠️  ANOMALY THRESHOLD EXCEEDED: %s has %d anomalies",
			srcIP, seh.anomalyCount[event.SrcIP])

		if seh.alertCallback != nil {
			seh.alertCallback(event)
		}

		// 重置计数器
		seh.anomalyCount[event.SrcIP] = 0
	}
}

// cleanupCounters 清理过期的计数器
func (seh *SecurityEventHandler) cleanupCounters() {
	for ip := range seh.anomalyCount {
		delete(seh.anomalyCount, ip)
	}
}

// LoadBalancerEventHandler 负载均衡事件处理器
type LoadBalancerEventHandler struct {
	decisions      map[uint32]uint64 // target_if -> count
	totalDecisions uint64
}

// NewLoadBalancerEventHandler 创建负载均衡事件处理器
func NewLoadBalancerEventHandler() *LoadBalancerEventHandler {
	return &LoadBalancerEventHandler{
		decisions: make(map[uint32]uint64),
	}
}

// HandleEvent 处理单个事件
func (lbeh *LoadBalancerEventHandler) HandleEvent(event *NetworkEvent) error {
	if event.EventType == EventTypeLoadBalance {
		lbeh.decisions[event.Ifindex]++
		lbeh.totalDecisions++

		if lbeh.totalDecisions%1000 == 0 {
			log.Printf("📊 Load Balancer: %d decisions made", lbeh.totalDecisions)
			lbeh.printDistribution()
		}
	}
	return nil
}

// HandleBatch 处理批量事件
func (lbeh *LoadBalancerEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		lbeh.HandleEvent(event)
	}
	return nil
}

// printDistribution 打印负载分布
func (lbeh *LoadBalancerEventHandler) printDistribution() {
	log.Println("Load Distribution:")
	for target, count := range lbeh.decisions {
		percentage := float64(count) / float64(lbeh.totalDecisions) * 100
		log.Printf("  Target %d: %d packets (%.1f%%)", target, count, percentage)
	}
}

// GetStats 获取负载均衡统计
func (lbeh *LoadBalancerEventHandler) GetStats() map[uint32]uint64 {
	stats := make(map[uint32]uint64)
	for k, v := range lbeh.decisions {
		stats[k] = v
	}
	return stats
}

// StatisticsEventHandler 统计事件处理器
type StatisticsEventHandler struct {
	packetCount    uint64
	byteCount      uint64
	protocolStats  map[uint8]uint64
	portStats      map[uint16]uint64
	lastReport     time.Time
	reportInterval time.Duration
}

// NewStatisticsEventHandler 创建统计事件处理器
func NewStatisticsEventHandler() *StatisticsEventHandler {
	return &StatisticsEventHandler{
		protocolStats:  make(map[uint8]uint64),
		portStats:      make(map[uint16]uint64),
		lastReport:     time.Now(),
		reportInterval: 30 * time.Second,
	}
}

// HandleEvent 处理单个事件
func (seh *StatisticsEventHandler) HandleEvent(event *NetworkEvent) error {
	seh.packetCount++
	seh.byteCount += uint64(event.PacketLen)
	seh.protocolStats[event.Protocol]++

	// 统计目标端口
	if event.DstPort != 0 {
		seh.portStats[event.DstPort]++
	}

	// 定期报告统计信息
	if time.Since(seh.lastReport) >= seh.reportInterval {
		seh.reportStatistics()
		seh.lastReport = time.Now()
	}

	return nil
}

// HandleBatch 处理批量事件
func (seh *StatisticsEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		seh.HandleEvent(event)
	}
	return nil
}

// reportStatistics 报告统计信息
func (seh *StatisticsEventHandler) reportStatistics() {
	log.Printf("📈 Statistics Report:")
	log.Printf("  Total Packets: %d", seh.packetCount)
	log.Printf("  Total Bytes: %s", formatBytes(seh.byteCount))

	// 协议分布
	log.Printf("  Protocol Distribution:")
	for proto, count := range seh.protocolStats {
		percentage := float64(count) / float64(seh.packetCount) * 100
		log.Printf("    %s: %d (%.1f%%)", getProtocolName(proto), count, percentage)
	}

	// 热门端口
	log.Printf("  Top Destination Ports:")
	type portStat struct {
		port  uint16
		count uint64
	}
	var topPorts []portStat
	for port, count := range seh.portStats {
		topPorts = append(topPorts, portStat{port, count})
	}

	// 简单排序（取前5个）
	for i := 0; i < len(topPorts) && i < 5; i++ {
		for j := i + 1; j < len(topPorts); j++ {
			if topPorts[j].count > topPorts[i].count {
				topPorts[i], topPorts[j] = topPorts[j], topPorts[i]
			}
		}
		percentage := float64(topPorts[i].count) / float64(seh.packetCount) * 100
		log.Printf("    Port %d: %d (%.1f%%)", topPorts[i].port, topPorts[i].count, percentage)
	}
}

// GetPacketCount 获取数据包计数
func (seh *StatisticsEventHandler) GetPacketCount() uint64 {
	return seh.packetCount
}

// GetByteCount 获取字节计数
func (seh *StatisticsEventHandler) GetByteCount() uint64 {
	return seh.byteCount
}

// GetProtocolStats 获取协议统计
func (seh *StatisticsEventHandler) GetProtocolStats() map[uint8]uint64 {
	stats := make(map[uint8]uint64)
	for k, v := range seh.protocolStats {
		stats[k] = v
	}
	return stats
}

// CompositeEventHandler 复合事件处理器，可组合多个处理器
type CompositeEventHandler struct {
	handlers []EventHandler
}

// NewCompositeEventHandler 创建复合事件处理器
func NewCompositeEventHandler() *CompositeEventHandler {
	return &CompositeEventHandler{
		handlers: make([]EventHandler, 0),
	}
}

// AddHandler 添加事件处理器
func (ceh *CompositeEventHandler) AddHandler(handler EventHandler) {
	ceh.handlers = append(ceh.handlers, handler)
}

// HandleEvent 处理单个事件
func (ceh *CompositeEventHandler) HandleEvent(event *NetworkEvent) error {
	for _, handler := range ceh.handlers {
		if err := handler.HandleEvent(event); err != nil {
			log.Printf("Handler error: %v", err)
		}
	}
	return nil
}

// HandleBatch 处理批量事件
func (ceh *CompositeEventHandler) HandleBatch(events []*NetworkEvent) error {
	for _, handler := range ceh.handlers {
		if err := handler.HandleBatch(events); err != nil {
			log.Printf("Batch handler error: %v", err)
		}
	}
	return nil
}
