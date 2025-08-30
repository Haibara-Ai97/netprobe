package ebpf

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

// IsSupported checks if the current system supports eBPF programs
// Verifies OS compatibility, memory limits, and required eBPF features
func IsSupported() bool {
	// eBPF is only available on Linux
	if runtime.GOOS != "linux" {
		return false
	}

	// Remove memory limit for eBPF - required for loading programs
	if err := rlimit.RemoveMemlock(); err != nil {
		return false
	}

	// Check if basic eBPF program types are supported
	if err := features.HaveProgType(ebpf.SocketFilter); err != nil {
		return false
	}

	// Check if basic eBPF map types are supported
	if err := features.HaveMapType(ebpf.Array); err != nil {
		return false
	}

	return true
}

// ManagerConfig 管理器配置
type ManagerConfig struct {
	// XDP配置
	XDPMode         XDPProgramType
	EnableXDPEvents bool

	// TC配置
	EnableTCEvents       bool
	EnableDetailedEvents bool

	// Ring Buffer配置
	BatchSize    int
	BatchTimeout time.Duration

	// 监控配置
	StatsReportInterval  time.Duration
	EnableSecurityAlerts bool
}

// DefaultManagerConfig 默认配置
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		XDPMode:              XDPAdvancedFilter,
		EnableXDPEvents:      false,
		EnableTCEvents:       true,
		EnableDetailedEvents: false,
		BatchSize:            100,
		BatchTimeout:         100 * time.Millisecond,
		StatsReportInterval:  60 * time.Second,
		EnableSecurityAlerts: true,
	}
}

// Manager coordinates eBPF program lifecycle and provides high-level API
// Manages loading, attachment, and cleanup of network monitoring programs
type Manager struct {
	networkLoader *NetworkLoader // Handles network-specific eBPF operations
	config        *ManagerConfig // Manager configuration

	// Event handlers
	securityHandler  *SecurityEventHandler     // Security event processing
	lbHandler        *LoadBalancerEventHandler // Load balancer event processing
	statsHandler     *StatisticsEventHandler   // Statistics event processing
	compositeHandler *CompositeEventHandler    // Composite handler

	// Runtime control
	ctx               context.Context
	cancel            context.CancelFunc
	monitoringActive  bool
	attachedInterface string
}

// NewManager creates a new eBPF manager instance
// Initializes all necessary components for network monitoring
func NewManager() *Manager {
	return NewManagerWithConfig(DefaultManagerConfig())
}

// NewManagerWithConfig creates a new eBPF manager with custom configuration
func NewManagerWithConfig(config *ManagerConfig) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	// Create event handlers
	securityHandler := NewSecurityEventHandler()
	lbHandler := NewLoadBalancerEventHandler()
	statsHandler := NewStatisticsEventHandler()

	// Create composite handler
	compositeHandler := NewCompositeEventHandler()
	compositeHandler.AddHandler(securityHandler)
	compositeHandler.AddHandler(lbHandler)
	compositeHandler.AddHandler(statsHandler)

	// Create network loader
	networkLoader := NewNetworkLoader()
	networkLoader.SetXDPProgramType(config.XDPMode)

	// Configure Ring Buffer
	rbConfig := &RingBufferConfig{
		EnableXDPEvents:      config.EnableXDPEvents,
		EnableTCEvents:       config.EnableTCEvents,
		EnableDetailedEvents: config.EnableDetailedEvents,
	}
	networkLoader.SetRingBufferConfig(rbConfig)

	manager := &Manager{
		networkLoader:    networkLoader,
		config:           config,
		securityHandler:  securityHandler,
		lbHandler:        lbHandler,
		statsHandler:     statsHandler,
		compositeHandler: compositeHandler,
		ctx:              ctx,
		cancel:           cancel,
		monitoringActive: false,
	}

	// Setup security alerts if enabled
	if config.EnableSecurityAlerts {
		securityHandler.SetAlertCallback(manager.handleSecurityAlert)
	}

	return manager
}

// LoadNetworkMonitor loads network monitoring eBPF programs into kernel
// Must be called before attaching programs to interfaces
func (m *Manager) LoadNetworkMonitor() error {
	log.Println("🚀 Loading eBPF network monitoring programs...")

	if err := m.networkLoader.LoadPrograms(); err != nil {
		return fmt.Errorf("loading eBPF programs: %w", err)
	}

	// Initialize Ring Buffer reader
	if err := m.networkLoader.InitializeRingBufferReader(m.ctx); err != nil {
		return fmt.Errorf("initializing ring buffer: %w", err)
	}

	// Add event handlers
	m.networkLoader.AddEventHandler(m.compositeHandler)

	log.Println("✅ eBPF programs loaded successfully")
	return nil
}

// AttachNetworkMonitor attaches loaded programs to specified network interface
// Interface must exist and be accessible for attachment to succeed
func (m *Manager) AttachNetworkMonitor(interfaceName string) error {
	if m.monitoringActive {
		return fmt.Errorf("monitoring is already active on interface %s", m.attachedInterface)
	}

	log.Printf("📡 Attaching network monitor to interface %s with %s mode...",
		interfaceName, m.getXDPModeString())

	if err := m.networkLoader.AttachNetworkPrograms(interfaceName); err != nil {
		return fmt.Errorf("attaching to interface %s: %w", interfaceName, err)
	}

	// Start Ring Buffer processing
	if err := m.networkLoader.StartRingBufferProcessing(); err != nil {
		return fmt.Errorf("starting ring buffer processing: %w", err)
	}

	// Start monitoring routines
	go m.monitoringLoop()
	go m.periodicStatsReport()

	m.attachedInterface = interfaceName
	m.monitoringActive = true

	log.Printf("✅ Network monitoring started on %s", interfaceName)
	return nil
}

// DetachNetworkMonitor detaches programs from the currently attached interface
func (m *Manager) DetachNetworkMonitor() error {
	if !m.monitoringActive {
		return fmt.Errorf("monitoring is not active")
	}

	log.Printf("🛑 Detaching network monitor from interface %s...", m.attachedInterface)

	m.cancel()
	m.monitoringActive = false
	m.attachedInterface = ""

	// Create new context for future use
	m.ctx, m.cancel = context.WithCancel(context.Background())

	log.Println("✅ Network monitoring detached")
	return nil
}

// SwitchXDPMode switches the XDP program mode
func (m *Manager) SwitchXDPMode(mode XDPProgramType) error {
	if m.config.XDPMode == mode {
		return nil
	}

	log.Printf("🔄 Switching XDP mode to %s", m.getXDPModeString(mode))

	// Update configuration
	m.config.XDPMode = mode
	m.networkLoader.SetXDPProgramType(mode)

	// If monitoring is active, reattach with new mode
	if m.monitoringActive {
		interfaceName := m.attachedInterface
		if err := m.DetachNetworkMonitor(); err != nil {
			return fmt.Errorf("detaching for mode switch: %w", err)
		}
		if err := m.AttachNetworkMonitor(interfaceName); err != nil {
			return fmt.Errorf("reattaching with new mode: %w", err)
		}
	}

	log.Printf("✅ Successfully switched to %s mode", m.getXDPModeString(mode))
	return nil
}

// Statistics and Security Management
func (m *Manager) GetNetworkStats() (map[string]uint64, error) {
	return m.networkLoader.GetStats()
}

func (m *Manager) GetGlobalStats() (*GlobalStats, error) {
	return m.networkLoader.ReadGlobalStats()
}

func (m *Manager) GetSecurityStats() (*SecurityStats, error) {
	return m.networkLoader.ReadSecurityStats()
}

func (m *Manager) GetLoadBalancerStats() (*LoadBalancerStats, error) {
	return m.networkLoader.ReadLoadBalancerStats()
}

func (m *Manager) AddIPToBlacklist(ip string) error {
	return m.networkLoader.AddToBlacklist(ip)
}

func (m *Manager) RemoveIPFromBlacklist(ip string) error {
	return m.networkLoader.RemoveFromBlacklist(ip)
}

func (m *Manager) GetBlacklistedIPs() ([]string, error) {
	return m.networkLoader.GetBlacklistedIPs()
}

// Configuration and State
func (m *Manager) UpdateConfig(config *ManagerConfig) {
	m.config = config
	m.networkLoader.SetXDPProgramType(config.XDPMode)
}

func (m *Manager) GetConfig() *ManagerConfig {
	return m.config
}

func (m *Manager) IsMonitoringActive() bool {
	return m.monitoringActive
}

func (m *Manager) GetAttachedInterface() string {
	return m.attachedInterface
}

func (m *Manager) GetCurrentXDPMode() XDPProgramType {
	return m.config.XDPMode
}

// Demo Methods
func (m *Manager) DemoBasicMonitoring(interfaceName string, duration time.Duration) error {
	log.Println("📊 Starting Basic Network Monitoring Demo")

	if err := m.SwitchXDPMode(XDPBasicMonitor); err != nil {
		return err
	}

	if !m.monitoringActive {
		if err := m.AttachNetworkMonitor(interfaceName); err != nil {
			return err
		}
	}

	time.Sleep(duration)
	m.printStats()
	return nil
}

func (m *Manager) DemoSecurityFiltering(interfaceName string, duration time.Duration) error {
	log.Println("🛡️ Starting Security Filtering Demo")

	if err := m.SwitchXDPMode(XDPAdvancedFilter); err != nil {
		return err
	}

	if !m.monitoringActive {
		if err := m.AttachNetworkMonitor(interfaceName); err != nil {
			return err
		}
	}

	time.Sleep(duration)
	m.printStats()
	return nil
}

func (m *Manager) DemoLoadBalancing(interfaceName string, duration time.Duration) error {
	log.Println("⚖️ Starting Load Balancing Demo")

	if err := m.SwitchXDPMode(XDPLoadBalancer); err != nil {
		return err
	}

	if !m.monitoringActive {
		if err := m.AttachNetworkMonitor(interfaceName); err != nil {
			return err
		}
	}

	time.Sleep(duration)
	m.printStats()
	return nil
}

// Utility methods
func (m *Manager) GetNetworkLoader() *NetworkLoader {
	return m.networkLoader
}

func (m *Manager) Close() error {
	if m.monitoringActive {
		m.DetachNetworkMonitor()
	}
	if m.networkLoader != nil {
		return m.networkLoader.Close()
	}
	return nil
}

// Internal monitoring loops
func (m *Manager) monitoringLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if m.config.XDPMode == XDPAdvancedFilter {
				m.networkLoader.ClearExpiredBlacklist()
			}
		}
	}
}

func (m *Manager) printStats() {
	if stats, err := m.GetGlobalStats(); err == nil {
		log.Printf("📈 Global Stats: %s", stats.String())
	}
	
	if m.config.XDPMode == XDPAdvancedFilter {
		if secStats, err := m.GetSecurityStats(); err == nil {
			log.Printf("🛡️ Security: DDoS Blocked=%d, Events=%d", 
				secStats.DDosBlocked, secStats.SecurityEvents)
		}
	}
	
	if m.config.XDPMode == XDPLoadBalancer {
		if lbStats, err := m.GetLoadBalancerStats(); err == nil {
			log.Printf("⚖️ Load Balancer: %d decisions", lbStats.LBDecisions)
		}
	}
}

func (m *Manager) getXDPModeString(mode XDPProgramType) string {
	switch mode {
	case XDPBasicMonitor:
		return "Basic Monitor"
	case XDPAdvancedFilter:
		return "Advanced Filter"
	case XDPLoadBalancer:
		return "Load Balancer"
	default:
		return "Unknown"
	}
}
