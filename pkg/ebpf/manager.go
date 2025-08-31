package ebpf

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// SimpleManagerConfig 简化的管理器配置
type SimpleManagerConfig struct {
	EnabledHooks        []HookPoint
	XDPMode             XDPProgramType
	StatsReportInterval time.Duration
	EnableDetailedLog   bool
}

// DefaultSimpleManagerConfig 默认简化配置
func DefaultSimpleManagerConfig() *SimpleManagerConfig {
	return &SimpleManagerConfig{
		EnabledHooks:        []HookPoint{HookXDP, HookTCIngress, HookTCEgress},
		XDPMode:             XDPAdvancedFilter,
		StatsReportInterval: 60 * time.Second,
		EnableDetailedLog:   false,
	}
}

// SimpleEBPFManager 简化的eBPF管理器
type SimpleEBPFManager struct {
	config            *SimpleManagerConfig
	networkLoader     *NetworkLoader
	handlers          map[string]EventHandler
	ctx               context.Context
	cancel            context.CancelFunc
	mutex             sync.RWMutex
	monitoringActive  bool
	attachedInterface string
	statsTimer        *time.Timer
}

// NewSimpleEBPFManager 创建简化的eBPF管理器
func NewSimpleEBPFManager() *SimpleEBPFManager {
	return NewSimpleEBPFManagerWithConfig(DefaultSimpleManagerConfig())
}

// NewSimpleEBPFManagerWithConfig 使用自定义配置创建eBPF管理器
func NewSimpleEBPFManagerWithConfig(config *SimpleManagerConfig) *SimpleEBPFManager {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &SimpleEBPFManager{
		config:   config,
		handlers: make(map[string]EventHandler),
		ctx:      ctx,
		cancel:   cancel,
	}

	// 创建网络加载器
	manager.networkLoader = NewNetworkLoader()
	manager.networkLoader.SetXDPProgramType(config.XDPMode)
	manager.networkLoader.SetRingBufferConfig(&RingBufferConfig{
		EnableXDPEvents: true,
		EnableTCEvents:  true,
	})

	// 初始化处理器
	manager.initHandlers()

	return manager
}

// initHandlers 初始化事件处理器
func (m *SimpleEBPFManager) initHandlers() {
	// 创建XDP处理器
	for _, hook := range m.config.EnabledHooks {
		if hook == HookXDP {
			handler := NewXDPHandler(&XDPHandlerConfig{
				EnableDetailedLogging: m.config.EnableDetailedLog,
				LogInterval:           30 * time.Second,
			})
			m.handlers[handler.GetName()] = handler
			log.Printf("✅ Initialized XDP handler")
			break
		}
	}

	// 创建TC处理器
	hasTC := false
	for _, hook := range m.config.EnabledHooks {
		if hook == HookTCIngress || hook == HookTCEgress {
			hasTC = true
			break
		}
	}
	if hasTC {
		handler := NewTCHandler(&TCHandlerConfig{
			EnableDetailedLogging: m.config.EnableDetailedLog,
			LogInterval:           30 * time.Second,
			TrackDirections:       true,
		})
		m.handlers[handler.GetName()] = handler
		log.Printf("✅ Initialized TC handler")
	}

	// 创建安全处理器
	handler := NewSecurityHandler(&SecurityHandlerConfig{
		AlertThreshold:  10,
		CleanupInterval: 5 * time.Minute,
		EnableAlerting:  true,
	})
	m.handlers[handler.GetName()] = handler
	log.Printf("✅ Initialized Security handler")
}

// LoadNetworkMonitor 加载网络监控eBPF程序到内核
func (m *SimpleEBPFManager) LoadNetworkMonitor() error {
	log.Println("🚀 Loading eBPF network monitoring programs...")

	if err := m.networkLoader.LoadPrograms(); err != nil {
		return fmt.Errorf("loading eBPF programs: %w", err)
	}

	// 初始化Ring Buffer读取器
	if err := m.networkLoader.InitializeRingBufferReader(m.ctx); err != nil {
		return fmt.Errorf("initializing ring buffer: %w", err)
	}

	// 添加事件处理器到网络加载器
	for _, handler := range m.handlers {
		m.networkLoader.AddEventHandler(handler)
	}

	log.Println("✅ eBPF programs loaded successfully")
	return nil
}

// AttachNetworkMonitor 将加载的程序附加到指定网络接口
func (m *SimpleEBPFManager) AttachNetworkMonitor(interfaceName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.monitoringActive {
		return fmt.Errorf("monitoring is already active on interface %s", m.attachedInterface)
	}

	log.Printf("📡 Attaching network monitor to interface %s...", interfaceName)

	if err := m.networkLoader.AttachNetworkPrograms(interfaceName); err != nil {
		return fmt.Errorf("attaching to interface %s: %w", interfaceName, err)
	}

	// 启动Ring Buffer处理
	if err := m.networkLoader.StartRingBufferProcessing(); err != nil {
		return fmt.Errorf("starting ring buffer processing: %w", err)
	}

	m.attachedInterface = interfaceName
	m.monitoringActive = true

	// 启动统计报告定时器
	m.startStatsReporting()

	log.Printf("✅ Network monitor attached to interface %s and started", interfaceName)
	return nil
}

// DetachNetworkMonitor 从网络接口分离程序
func (m *SimpleEBPFManager) DetachNetworkMonitor() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.monitoringActive {
		return nil
	}

	log.Printf("📡 Detaching network monitor from interface %s...", m.attachedInterface)

	// 停止统计报告定时器
	if m.statsTimer != nil {
		m.statsTimer.Stop()
		m.statsTimer = nil
	}

	// 关闭网络加载器
	if err := m.networkLoader.Close(); err != nil {
		log.Printf("⚠️  Error closing network loader: %v", err)
	}

	m.monitoringActive = false
	m.attachedInterface = ""

	log.Println("✅ Network monitor detached")
	return nil
}

// Close 关闭管理器并清理资源
func (m *SimpleEBPFManager) Close() error {
	m.DetachNetworkMonitor()

	if m.cancel != nil {
		m.cancel()
	}

	log.Println("✅ Simple eBPF Manager closed")
	return nil
}

// GetHandlerQueryInterface 根据处理器名称获取查询接口
func (m *SimpleEBPFManager) GetHandlerQueryInterface(handlerName string) (QueryInterface, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	handler, exists := m.handlers[handlerName]
	if !exists {
		return nil, fmt.Errorf("handler '%s' not found", handlerName)
	}

	return handler.GetQueryInterface(), nil
}

// GetXDPStats 获取XDP统计信息
func (m *SimpleEBPFManager) GetXDPStats() (*TrafficStats, error) {
	queryInterface, err := m.GetHandlerQueryInterface("XDP Handler")
	if err != nil {
		return nil, err
	}

	return queryInterface.GetTotalStats(), nil
}

// GetTCStats 获取TC统计信息
func (m *SimpleEBPFManager) GetTCStats() (*TrafficStats, error) {
	queryInterface, err := m.GetHandlerQueryInterface("TC Handler")
	if err != nil {
		return nil, err
	}

	return queryInterface.GetTotalStats(), nil
}

// GetTCIngressStats 获取TC Ingress统计信息
func (m *SimpleEBPFManager) GetTCIngressStats() (*TrafficStats, error) {
	queryInterface, err := m.GetHandlerQueryInterface("TC Handler")
	if err != nil {
		return nil, err
	}

	return queryInterface.GetHookStats(HookTCIngress), nil
}

// GetTCEgressStats 获取TC Egress统计信息
func (m *SimpleEBPFManager) GetTCEgressStats() (*TrafficStats, error) {
	queryInterface, err := m.GetHandlerQueryInterface("TC Handler")
	if err != nil {
		return nil, err
	}

	return queryInterface.GetHookStats(HookTCEgress), nil
}

// GetSecurityStats 获取安全统计信息
func (m *SimpleEBPFManager) GetSecurityStats() (*TrafficStats, error) {
	queryInterface, err := m.GetHandlerQueryInterface("Security Handler")
	if err != nil {
		return nil, err
	}

	return queryInterface.GetTotalStats(), nil
}

// ResetAllStats 重置所有处理器的统计信息
func (m *SimpleEBPFManager) ResetAllStats() error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, handler := range m.handlers {
		queryInterface := handler.GetQueryInterface()
		queryInterface.ResetStats()
	}

	log.Println("📊 All handler statistics have been reset")
	return nil
}

// IsMonitoringActive 检查监控是否活跃
func (m *SimpleEBPFManager) IsMonitoringActive() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.monitoringActive
}

// GetAttachedInterface 获取当前附加的接口
func (m *SimpleEBPFManager) GetAttachedInterface() string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.attachedInterface
}

// startStatsReporting 启动统计报告
func (m *SimpleEBPFManager) startStatsReporting() {
	if m.config.StatsReportInterval <= 0 {
		return
	}

	m.statsTimer = time.AfterFunc(m.config.StatsReportInterval, func() {
		m.reportStats()
		// 重新设置定时器
		if m.monitoringActive {
			m.startStatsReporting()
		}
	})
}

// reportStats 报告统计信息
func (m *SimpleEBPFManager) reportStats() {
	log.Printf("📊 === Simple eBPF Manager Statistics Report ===")

	// 报告各处理器统计
	for name, handler := range m.handlers {
		queryInterface := handler.GetQueryInterface()
		stats := queryInterface.GetTotalStats()

		log.Printf("Handler [%s]:", name)
		log.Printf("  Packets: %d", stats.PacketCount)
		log.Printf("  Bytes: %s", formatBytes(stats.ByteCount))

		if len(stats.ProtocolStats) > 0 && stats.PacketCount > 0 {
			log.Printf("  Top Protocols:")
			for proto, count := range stats.ProtocolStats {
				if count > 0 {
					percentage := float64(count) / float64(stats.PacketCount) * 100
					log.Printf("    %s: %d (%.1f%%)", getProtocolName(proto), count, percentage)
				}
			}
		}
	}

	log.Printf("===========================================")
}

// SetSecurityAlertCallback 设置安全告警回调
func (m *SimpleEBPFManager) SetSecurityAlertCallback(callback func(event *NetworkEvent)) error {
	handler, exists := m.handlers["Security Handler"]
	if !exists {
		return fmt.Errorf("security handler not found")
	}

	if securityHandler, ok := handler.(*SecurityHandler); ok {
		securityHandler.SetAlertCallback(callback)
		return nil
	}

	return fmt.Errorf("security handler type assertion failed")
}
