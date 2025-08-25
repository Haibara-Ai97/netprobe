package ebpf

import (
"runtime"

"github.com/cilium/ebpf"
"github.com/cilium/ebpf/features"
"github.com/cilium/ebpf/rlimit"
)

// IsSupported 检查当前系统是否支持 eBPF
func IsSupported() bool {
if runtime.GOOS != "linux" {
return false
}

if err := rlimit.RemoveMemlock(); err != nil {
return false
}

if err := features.HaveProgType(ebpf.SocketFilter); err != nil {
return false
}

if err := features.HaveMapType(ebpf.Array); err != nil {
return false
}

return true
}

// Manager 管理 eBPF 程序的生命周期
type Manager struct {
networkLoader *NetworkLoader
}

// NewManager 创建新的 eBPF 管理器
func NewManager() *Manager {
return &Manager{
networkLoader: NewNetworkLoader(),
}
}

// LoadNetworkMonitor 加载网络监控程序
func (m *Manager) LoadNetworkMonitor() error {
return m.networkLoader.LoadPrograms()
}

// AttachNetworkMonitor 附加网络监控程序到指定接口
func (m *Manager) AttachNetworkMonitor(interfaceName string) error {
return m.networkLoader.AttachNetworkPrograms(interfaceName)
}

// GetNetworkStats 获取网络统计信息
func (m *Manager) GetNetworkStats() (map[string]uint64, error) {
return m.networkLoader.GetStats()
}

// GetNetworkLoader 获取网络加载器
func (m *Manager) GetNetworkLoader() *NetworkLoader {
return m.networkLoader
}

// Close 关闭管理器
func (m *Manager) Close() error {
if m.networkLoader != nil {
return m.networkLoader.Close()
}
return nil
}
