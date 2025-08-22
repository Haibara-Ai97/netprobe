package ebpf

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
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

	// 使用 features 包检测 eBPF 支持
	if err := features.HaveProgType(ebpf.SocketFilter); err != nil {
		return false
	}

	// 检查 Map 支持
	if err := features.HaveMapType(ebpf.Array); err != nil {
		return false
	}

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

// ListPrograms 列出所有已加载的程序名称
func (m *Manager) ListPrograms() []string {
	names := make([]string, 0, len(m.programs))
	for name := range m.programs {
		names = append(names, name)
	}
	return names
}

// GetProgramCount 获取已加载程序的数量
func (m *Manager) GetProgramCount() int {
	return len(m.programs)
}

// HasProgram 检查是否已加载指定名称的程序
func (m *Manager) HasProgram(name string) bool {
	_, exists := m.programs[name]
	return exists
}

// Close 关闭管理器并清理所有程序
func (m *Manager) Close() error {
	var errors []error

	for name, prog := range m.programs {
		if err := prog.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close program %s: %w", name, err))
		}
	}

	// 清空程序映射
	m.programs = make(map[string]*Program)

	// 如果有错误，返回合并的错误信息
	if len(errors) > 0 {
		errorMsg := "multiple errors occurred while closing programs:"
		for _, err := range errors {
			errorMsg += "\n  - " + err.Error()
		}
		return fmt.Errorf(errorMsg)
	}

	return nil
}

// ReloadProgram 重新加载指定的程序
func (m *Manager) ReloadProgram(name string, spec *ProgramSpec) error {
	// 先卸载现有程序
	if m.HasProgram(name) {
		if err := m.UnloadProgram(name); err != nil {
			return fmt.Errorf("failed to unload existing program %s: %w", name, err)
		}
	}

	// 加载新程序
	return m.LoadProgram(name, spec)
}

// LoadProgramFromObject 从对象文件加载程序
func (m *Manager) LoadProgramFromObject(name, objectFile, section, attachTo string, progType ProgramType) error {
	spec := &ProgramSpec{
		Name:       name,
		Type:       progType,
		ObjectFile: objectFile,
		Section:    section,
		AttachTo:   attachTo,
	}

	return m.LoadProgram(name, spec)
}

// GetProgramMap 获取指定程序的指定 Map
func (m *Manager) GetProgramMap(programName, mapName string) (*ebpf.Map, error) {
	prog, err := m.GetProgram(programName)
	if err != nil {
		return nil, err
	}

	return prog.GetMap(mapName)
}
