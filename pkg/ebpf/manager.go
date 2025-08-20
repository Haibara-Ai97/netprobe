package ebpf

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// IsSupported 检查当前系统是否支持 eBPF
func IsSupported() bool {
	// 检查操作系统
	if runtime.GOOS != "linux" {
		return false
	}

	// 检查 eBPF 基本功能
	if err := rlimit.RemoveMemlock(); err != nil {
		return false
	}

	// 尝试创建一个简单的 eBPF 程序来测试支持
	spec := &ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: ebpf.Instructions{
			// 简单的返回 0 的程序
			ebpf.Mov.Imm(ebpf.Reg0, 0),
			ebpf.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		return false
	}
	prog.Close()

	return true
}

// Manager 管理 eBPF 程序的生命周期
type Manager struct {
	programs map[string]*Program
}

// NewManager 创建新的 eBPF 管理器
func NewManager() *Manager {
	return &Manager{
		programs: make(map[string]*Program),
	}
}

// LoadProgram 加载 eBPF 程序
func (m *Manager) LoadProgram(name string, spec *ProgramSpec) error {
	prog, err := NewProgram(spec)
	if err != nil {
		return fmt.Errorf("failed to load program %s: %w", name, err)
	}

	m.programs[name] = prog
	return nil
}

// UnloadProgram 卸载 eBPF 程序
func (m *Manager) UnloadProgram(name string) error {
	prog, exists := m.programs[name]
	if !exists {
		return fmt.Errorf("program %s not found", name)
	}

	if err := prog.Close(); err != nil {
		return fmt.Errorf("failed to close program %s: %w", name, err)
	}

	delete(m.programs, name)
	return nil
}

// GetProgram 获取指定的 eBPF 程序
func (m *Manager) GetProgram(name string) (*Program, error) {
	prog, exists := m.programs[name]
	if !exists {
		return nil, fmt.Errorf("program %s not found", name)
	}
	return prog, nil
}

// Close 关闭管理器并清理所有程序
func (m *Manager) Close() error {
	var lastErr error
	for name, prog := range m.programs {
		if err := prog.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close program %s: %w", name, err)
		}
	}
	m.programs = make(map[string]*Program)
	return lastErr
}
