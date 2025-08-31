package ebpf

import (
	"log"
	"sync"
	"time"
)

// XDPHandler XDP钩子点事件处理器
type XDPHandler struct {
	name           string
	supportedHooks []HookPoint
	stats          *TrafficStats
	config         *XDPHandlerConfig
	mutex          sync.RWMutex
}

type XDPHandlerConfig struct {
	EnableDetailedLogging bool
	LogInterval           time.Duration
}

// NewXDPHandler 创建XDP事件处理器
func NewXDPHandler(config *XDPHandlerConfig) *XDPHandler {
	if config == nil {
		config = &XDPHandlerConfig{
			EnableDetailedLogging: false,
			LogInterval:           30 * time.Second,
		}
	}

	return &XDPHandler{
		name:           "XDP Handler",
		supportedHooks: []HookPoint{HookXDP},
		stats:          NewTrafficStats(),
		config:         config,
	}
}

// GetName 获取处理器名称
func (h *XDPHandler) GetName() string {
	return h.name
}

// GetSupportedHooks 获取支持的钩子点
func (h *XDPHandler) GetSupportedHooks() []HookPoint {
	return h.supportedHooks
}

// HandleEvent 处理单个事件
func (h *XDPHandler) HandleEvent(event *NetworkEvent) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// 只处理XDP钩子点的事件
	if HookPoint(event.HookPoint) != HookXDP {
		return nil
	}

	// 更新统计信息
	h.updateStats(event)

	// 可选的详细日志
	if h.config.EnableDetailedLogging {
		h.logEvent(event)
	}

	return nil
}

// HandleBatch 处理批量事件
func (h *XDPHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		if err := h.HandleEvent(event); err != nil {
			return err
		}
	}
	return nil
}

// GetQueryInterface 获取查询接口
func (h *XDPHandler) GetQueryInterface() QueryInterface {
	return &XDPQueryInterface{handler: h}
}

// updateStats 更新统计信息
func (h *XDPHandler) updateStats(event *NetworkEvent) {
	h.stats.PacketCount++
	h.stats.ByteCount += uint64(event.PacketLen)
	h.stats.ProtocolStats[event.Protocol]++

	if event.DstPort != 0 {
		h.stats.PortStats[event.DstPort]++
	}

	h.stats.LastSeen = time.Now()
}

// logEvent 记录事件日志
func (h *XDPHandler) logEvent(event *NetworkEvent) {
	log.Printf("[XDP] %s", event.String())
}

// XDPQueryInterface XDP查询接口
type XDPQueryInterface struct {
	handler *XDPHandler
}

// GetTotalStats 获取总体统计信息
func (q *XDPQueryInterface) GetTotalStats() *TrafficStats {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()
	return q.handler.stats.Clone()
}

// GetHookStats 获取指定钩子点的统计信息
func (q *XDPQueryInterface) GetHookStats(hook HookPoint) *TrafficStats {
	if hook == HookXDP {
		return q.GetTotalStats()
	}
	return NewTrafficStats()
}

// GetProtocolDistribution 获取协议分布统计
func (q *XDPQueryInterface) GetProtocolDistribution() map[uint8]uint64 {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()

	result := make(map[uint8]uint64)
	for k, v := range q.handler.stats.ProtocolStats {
		result[k] = v
	}
	return result
}

// GetPortStats 获取端口统计
func (q *XDPQueryInterface) GetPortStats() map[uint16]uint64 {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()

	result := make(map[uint16]uint64)
	for k, v := range q.handler.stats.PortStats {
		result[k] = v
	}
	return result
}

// ResetStats 重置统计信息
func (q *XDPQueryInterface) ResetStats() {
	q.handler.mutex.Lock()
	defer q.handler.mutex.Unlock()
	q.handler.stats = NewTrafficStats()
}

// TCHandler TC钩子点事件处理器
type TCHandler struct {
	name           string
	supportedHooks []HookPoint
	ingressStats   *TrafficStats
	egressStats    *TrafficStats
	config         *TCHandlerConfig
	mutex          sync.RWMutex
}

type TCHandlerConfig struct {
	EnableDetailedLogging bool
	LogInterval           time.Duration
	TrackDirections       bool
}

// NewTCHandler 创建TC事件处理器
func NewTCHandler(config *TCHandlerConfig) *TCHandler {
	if config == nil {
		config = &TCHandlerConfig{
			EnableDetailedLogging: false,
			LogInterval:           30 * time.Second,
			TrackDirections:       true,
		}
	}

	return &TCHandler{
		name:           "TC Handler",
		supportedHooks: []HookPoint{HookTCIngress, HookTCEgress},
		ingressStats:   NewTrafficStats(),
		egressStats:    NewTrafficStats(),
		config:         config,
	}
}

// GetName 获取处理器名称
func (h *TCHandler) GetName() string {
	return h.name
}

// GetSupportedHooks 获取支持的钩子点
func (h *TCHandler) GetSupportedHooks() []HookPoint {
	return h.supportedHooks
}

// HandleEvent 处理单个事件
func (h *TCHandler) HandleEvent(event *NetworkEvent) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	hookPoint := HookPoint(event.HookPoint)

	// 只处理TC钩子点的事件
	if hookPoint != HookTCIngress && hookPoint != HookTCEgress {
		return nil
	}

	// 根据钩子点更新对应的统计信息
	var stats *TrafficStats
	switch hookPoint {
	case HookTCIngress:
		stats = h.ingressStats
	case HookTCEgress:
		stats = h.egressStats
	default:
		return nil
	}

	// 更新统计信息
	h.updateStats(stats, event)

	// 可选的详细日志
	if h.config.EnableDetailedLogging {
		h.logEvent(event, hookPoint)
	}

	return nil
}

// HandleBatch 处理批量事件
func (h *TCHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		if err := h.HandleEvent(event); err != nil {
			return err
		}
	}
	return nil
}

// GetQueryInterface 获取查询接口
func (h *TCHandler) GetQueryInterface() QueryInterface {
	return &TCQueryInterface{handler: h}
}

// updateStats 更新统计信息
func (h *TCHandler) updateStats(stats *TrafficStats, event *NetworkEvent) {
	stats.PacketCount++
	stats.ByteCount += uint64(event.PacketLen)
	stats.ProtocolStats[event.Protocol]++

	if event.DstPort != 0 {
		stats.PortStats[event.DstPort]++
	}

	stats.LastSeen = time.Now()
}

// logEvent 记录事件日志
func (h *TCHandler) logEvent(event *NetworkEvent, hookPoint HookPoint) {
	log.Printf("[TC-%s] %s", hookPoint.String(), event.String())
}

// TCQueryInterface TC查询接口
type TCQueryInterface struct {
	handler *TCHandler
}

// GetTotalStats 获取总体统计信息（合并ingress和egress）
func (q *TCQueryInterface) GetTotalStats() *TrafficStats {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()

	total := NewTrafficStats()
	total.PacketCount = q.handler.ingressStats.PacketCount + q.handler.egressStats.PacketCount
	total.ByteCount = q.handler.ingressStats.ByteCount + q.handler.egressStats.ByteCount

	// 合并协议统计
	for proto, count := range q.handler.ingressStats.ProtocolStats {
		total.ProtocolStats[proto] += count
	}
	for proto, count := range q.handler.egressStats.ProtocolStats {
		total.ProtocolStats[proto] += count
	}

	// 合并端口统计
	for port, count := range q.handler.ingressStats.PortStats {
		total.PortStats[port] += count
	}
	for port, count := range q.handler.egressStats.PortStats {
		total.PortStats[port] += count
	}

	// 设置时间范围
	if q.handler.ingressStats.FirstSeen.Before(q.handler.egressStats.FirstSeen) {
		total.FirstSeen = q.handler.ingressStats.FirstSeen
	} else {
		total.FirstSeen = q.handler.egressStats.FirstSeen
	}

	if q.handler.ingressStats.LastSeen.After(q.handler.egressStats.LastSeen) {
		total.LastSeen = q.handler.ingressStats.LastSeen
	} else {
		total.LastSeen = q.handler.egressStats.LastSeen
	}

	return total
}

// GetHookStats 获取指定钩子点的统计信息
func (q *TCQueryInterface) GetHookStats(hook HookPoint) *TrafficStats {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()

	switch hook {
	case HookTCIngress:
		return q.handler.ingressStats.Clone()
	case HookTCEgress:
		return q.handler.egressStats.Clone()
	default:
		return NewTrafficStats()
	}
}

// GetProtocolDistribution 获取协议分布统计
func (q *TCQueryInterface) GetProtocolDistribution() map[uint8]uint64 {
	total := q.GetTotalStats()
	return total.ProtocolStats
}

// GetPortStats 获取端口统计
func (q *TCQueryInterface) GetPortStats() map[uint16]uint64 {
	total := q.GetTotalStats()
	return total.PortStats
}

// ResetStats 重置统计信息
func (q *TCQueryInterface) ResetStats() {
	q.handler.mutex.Lock()
	defer q.handler.mutex.Unlock()
	q.handler.ingressStats = NewTrafficStats()
	q.handler.egressStats = NewTrafficStats()
}

// SecurityHandler 安全事件处理器
type SecurityHandler struct {
	name           string
	supportedHooks []HookPoint
	alertThreshold int
	anomalyCount   map[uint32]int // IP -> count
	lastCleanup    time.Time
	alertCallback  func(event *NetworkEvent)
	stats          *TrafficStats
	config         *SecurityHandlerConfig
	mutex          sync.RWMutex
}

type SecurityHandlerConfig struct {
	AlertThreshold  int
	CleanupInterval time.Duration
	EnableAlerting  bool
}

// NewSecurityHandler 创建安全事件处理器
func NewSecurityHandler(config *SecurityHandlerConfig) *SecurityHandler {
	if config == nil {
		config = &SecurityHandlerConfig{
			AlertThreshold:  10,
			CleanupInterval: 5 * time.Minute,
			EnableAlerting:  true,
		}
	}

	return &SecurityHandler{
		name:           "Security Handler",
		supportedHooks: []HookPoint{HookXDP, HookTCIngress, HookTCEgress}, // 支持所有钩子点
		alertThreshold: config.AlertThreshold,
		anomalyCount:   make(map[uint32]int),
		lastCleanup:    time.Now(),
		stats:          NewTrafficStats(),
		config:         config,
	}
}

// GetName 获取处理器名称
func (h *SecurityHandler) GetName() string {
	return h.name
}

// GetSupportedHooks 获取支持的钩子点
func (h *SecurityHandler) GetSupportedHooks() []HookPoint {
	return h.supportedHooks
}

// SetAlertCallback 设置告警回调函数
func (h *SecurityHandler) SetAlertCallback(callback func(event *NetworkEvent)) {
	h.alertCallback = callback
}

// HandleEvent 处理单个事件
func (h *SecurityHandler) HandleEvent(event *NetworkEvent) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// 处理安全相关事件
	switch event.EventType {
	case EventTypeSecurity:
		h.handleSecurityEvent(event)
	case EventTypeDDoS:
		h.handleDDoSEvent(event)
	case EventTypeAnomaly:
		h.handleAnomalyEvent(event)
	}

	// 更新统计信息
	h.updateStats(event)

	// 定期清理计数器
	if time.Since(h.lastCleanup) > h.config.CleanupInterval {
		h.cleanupCounters()
		h.lastCleanup = time.Now()
	}

	return nil
}

// HandleBatch 处理批量事件
func (h *SecurityHandler) HandleBatch(events []*NetworkEvent) error {
	for _, event := range events {
		if err := h.HandleEvent(event); err != nil {
			return err
		}
	}
	return nil
}

// GetQueryInterface 获取查询接口
func (h *SecurityHandler) GetQueryInterface() QueryInterface {
	return &SecurityQueryInterface{handler: h}
}

// handleSecurityEvent 处理安全事件
func (h *SecurityHandler) handleSecurityEvent(event *NetworkEvent) {
	srcIP := intToIP(event.SrcIP)
	log.Printf("🚨 SECURITY ALERT: Suspicious packet from %s (size: %d bytes)", srcIP, event.PacketLen)

	if h.config.EnableAlerting && h.alertCallback != nil {
		h.alertCallback(event)
	}
}

// handleDDoSEvent 处理DDoS事件
func (h *SecurityHandler) handleDDoSEvent(event *NetworkEvent) {
	srcIP := intToIP(event.SrcIP)
	log.Printf("🛡️  DDoS DETECTED: Rate limit exceeded from %s, packet blocked", srcIP)

	if h.config.EnableAlerting && h.alertCallback != nil {
		h.alertCallback(event)
	}
}

// handleAnomalyEvent 处理异常事件
func (h *SecurityHandler) handleAnomalyEvent(event *NetworkEvent) {
	h.anomalyCount[event.SrcIP]++

	if h.anomalyCount[event.SrcIP] >= h.alertThreshold {
		srcIP := intToIP(event.SrcIP)
		log.Printf("⚠️  ANOMALY THRESHOLD EXCEEDED: %s has %d anomalies", srcIP, h.anomalyCount[event.SrcIP])

		if h.config.EnableAlerting && h.alertCallback != nil {
			h.alertCallback(event)
		}

		// 重置计数器
		h.anomalyCount[event.SrcIP] = 0
	}
}

// updateStats 更新统计信息
func (h *SecurityHandler) updateStats(event *NetworkEvent) {
	h.stats.PacketCount++
	h.stats.ByteCount += uint64(event.PacketLen)
	h.stats.ProtocolStats[event.Protocol]++

	if event.DstPort != 0 {
		h.stats.PortStats[event.DstPort]++
	}

	h.stats.LastSeen = time.Now()
}

// cleanupCounters 清理计数器
func (h *SecurityHandler) cleanupCounters() {
	for ip := range h.anomalyCount {
		delete(h.anomalyCount, ip)
	}
}

// SecurityQueryInterface 安全查询接口
type SecurityQueryInterface struct {
	handler *SecurityHandler
}

// GetTotalStats 获取总体统计信息
func (q *SecurityQueryInterface) GetTotalStats() *TrafficStats {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()
	return q.handler.stats.Clone()
}

// GetHookStats 获取指定钩子点的统计信息
func (q *SecurityQueryInterface) GetHookStats(hook HookPoint) *TrafficStats {
	// 安全处理器统计信息不区分钩子点
	return q.GetTotalStats()
}

// GetProtocolDistribution 获取协议分布统计
func (q *SecurityQueryInterface) GetProtocolDistribution() map[uint8]uint64 {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()

	result := make(map[uint8]uint64)
	for k, v := range q.handler.stats.ProtocolStats {
		result[k] = v
	}
	return result
}

// GetPortStats 获取端口统计
func (q *SecurityQueryInterface) GetPortStats() map[uint16]uint64 {
	q.handler.mutex.RLock()
	defer q.handler.mutex.RUnlock()

	result := make(map[uint16]uint64)
	for k, v := range q.handler.stats.PortStats {
		result[k] = v
	}
	return result
}

// ResetStats 重置统计信息
func (q *SecurityQueryInterface) ResetStats() {
	q.handler.mutex.Lock()
	defer q.handler.mutex.Unlock()
	q.handler.stats = NewTrafficStats()
	q.handler.anomalyCount = make(map[uint32]int)
}
