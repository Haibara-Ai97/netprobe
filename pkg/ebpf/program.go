package ebpf

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ProgramType 定义 eBPF 程序类型
type ProgramType string

const (
	ProgramTypeXDP          ProgramType = "xdp"
	ProgramTypeTC           ProgramType = "tc"
	ProgramTypeSocketFilter ProgramType = "socket_filter"
	ProgramTypeKprobe       ProgramType = "kprobe"
	ProgramTypeKretprobe    ProgramType = "kretprobe"
	ProgramTypeTracepoint   ProgramType = "tracepoint"
	ProgramTypeUprobe       ProgramType = "uprobe"
	ProgramTypeUretprobe    ProgramType = "uretprobe"
)

// ProgramSpec 定义 eBPF 程序规范
type ProgramSpec struct {
	Name       string
	Type       ProgramType
	ObjectFile string
	Section    string
	AttachTo   string // 网络接口名、函数名等
}

// Program 表示一个已加载的 eBPF 程序
type Program struct {
	spec    *ProgramSpec
	program *ebpf.Program
	link    link.Link
	maps    map[string]*ebpf.Map
}

// NewProgram 创建并加载新的 eBPF 程序
func NewProgram(spec *ProgramSpec) (*Program, error) {
	// 从对象文件加载程序
	progSpec, err := loadProgramFromFile(spec.ObjectFile, spec.Section)
	if err != nil {
		return nil, fmt.Errorf("failed to load program from file: %w", err)
	}

	// 创建程序
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF program: %w", err)
	}

	p := &Program{
		spec:    spec,
		program: prog,
		maps:    make(map[string]*ebpf.Map),
	}

	// 加载相关的 Maps (如果需要)
	if err := p.loadMaps(spec.ObjectFile); err != nil {
		prog.Close()
		return nil, fmt.Errorf("failed to load maps: %w", err)
	}

	// 附加程序到指定位置
	if err := p.attach(); err != nil {
		prog.Close()
		return nil, fmt.Errorf("failed to attach program: %w", err)
	}

	return p, nil
}

// loadMaps 从对象文件加载相关的 Maps
func (p *Program) loadMaps(objectFile string) error {
	// 从对象文件加载 Collection 规范
	spec, err := ebpf.LoadCollectionSpec(objectFile)
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}

	// 为每个 Map 创建实例
	for name, mapSpec := range spec.Maps {
		m, err := ebpf.NewMap(mapSpec)
		if err != nil {
			return fmt.Errorf("failed to create map %s: %w", name, err)
		}
		p.maps[name] = m
	}

	return nil
}

// attach 将程序附加到指定位置
func (p *Program) attach() error {
	switch p.spec.Type {
	case ProgramTypeXDP:
		return p.attachXDP()
	case ProgramTypeTC:
		return p.attachTC()
	case ProgramTypeKprobe:
		return p.attachKprobe()
	case ProgramTypeKretprobe:
		return p.attachKretprobe()
	case ProgramTypeTracepoint:
		return p.attachTracepoint()
	default:
		return fmt.Errorf("unsupported program type: %s", p.spec.Type)
	}
}

// attachXDP 附加 XDP 程序
func (p *Program) attachXDP() error {
	// AttachTo 应该是网络接口名称
	iface, err := net.InterfaceByName(p.spec.AttachTo)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", p.spec.AttachTo, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   p.program,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP program to %s: %w", p.spec.AttachTo, err)
	}
	p.link = l
	return nil
}

// attachTC 附加 TC 程序
func (p *Program) attachTC() error {
	// TC 程序需要更复杂的附加逻辑
	// 这里是简化版本，实际实现需要处理 qdisc 和 filter
	return fmt.Errorf("TC program attachment not implemented yet")
}

// attachKprobe 附加 kprobe 程序
func (p *Program) attachKprobe() error {
	l, err := link.Kprobe(p.spec.AttachTo, p.program, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe to %s: %w", p.spec.AttachTo, err)
	}
	p.link = l
	return nil
}

// attachKretprobe 附加 kretprobe 程序
func (p *Program) attachKretprobe() error {
	l, err := link.Kretprobe(p.spec.AttachTo, p.program, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kretprobe to %s: %w", p.spec.AttachTo, err)
	}
	p.link = l
	return nil
}

// attachTracepoint 附加 tracepoint 程序
func (p *Program) attachTracepoint() error {
	// AttachTo 格式应该是 "group:name"，例如 "net:net_dev_queue"
	group := "net" // 默认组
	name := p.spec.AttachTo

	l, err := link.Tracepoint(group, name, p.program, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint %s:%s: %w", group, name, err)
	}
	p.link = l
	return nil
}

// GetMap 获取程序中的指定 map
func (p *Program) GetMap(name string) (*ebpf.Map, error) {
	if m, exists := p.maps[name]; exists {
		return m, nil
	}
	return nil, fmt.Errorf("map %s not found", name)
}

// Close 关闭程序并清理资源
func (p *Program) Close() error {
	var lastErr error

	// 分离程序
	if p.link != nil {
		if err := p.link.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close link: %w", err)
		}
	}

	// 关闭 maps
	for name, m := range p.maps {
		if err := m.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close map %s: %w", name, err)
		}
	}

	// 关闭程序
	if p.program != nil {
		if err := p.program.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close program: %w", err)
		}
	}

	return lastErr
}

// loadProgramFromFile 从对象文件加载程序规范
func loadProgramFromFile(objectFile, section string) (*ebpf.ProgramSpec, error) {
	// 确保文件路径是绝对路径
	absPath, err := filepath.Abs(objectFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// 从对象文件加载 Collection 规范
	spec, err := ebpf.LoadCollectionSpec(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec from %s: %w", absPath, err)
	}

	// 查找指定的程序段
	progSpec, exists := spec.Programs[section]
	if !exists {
		return nil, fmt.Errorf("program section %s not found in %s", section, absPath)
	}

	return progSpec, nil
}
