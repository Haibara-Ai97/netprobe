package ebpf

import (
	"runtime"

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

// Manager coordinates eBPF program lifecycle and provides high-level API
// Manages loading, attachment, and cleanup of network monitoring programs
type Manager struct {
	networkLoader *NetworkLoader // Handles network-specific eBPF operations
}

// NewManager creates a new eBPF manager instance
// Initializes all necessary components for network monitoring
func NewManager() *Manager {
	return &Manager{
		networkLoader: NewNetworkLoader(),
	}
}

// LoadNetworkMonitor loads network monitoring eBPF programs into kernel
// Must be called before attaching programs to interfaces
func (m *Manager) LoadNetworkMonitor() error {
	return m.networkLoader.LoadPrograms()
}

// AttachNetworkMonitor attaches loaded programs to specified network interface
// Interface must exist and be accessible for attachment to succeed
func (m *Manager) AttachNetworkMonitor(interfaceName string) error {
	return m.networkLoader.AttachNetworkPrograms(interfaceName)
}

// GetNetworkStats retrieves current network statistics from eBPF maps
// Returns aggregated statistics across all monitored interfaces
func (m *Manager) GetNetworkStats() (map[string]uint64, error) {
	return m.networkLoader.GetStats()
}

// GetNetworkLoader provides direct access to network loader for advanced operations
// Useful for accessing eBPF maps and performing custom data collection
func (m *Manager) GetNetworkLoader() *NetworkLoader {
	return m.networkLoader
}

// Close cleans up all eBPF resources and detaches programs
// Should be called before program termination to prevent resource leaks
func (m *Manager) Close() error {
	if m.networkLoader != nil {
		return m.networkLoader.Close()
	}
	return nil
}
