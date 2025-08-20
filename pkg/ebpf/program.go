package ebpf

import (
	"fmt"
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

	// 附加程序到指定位置
	if err := p.attach(); err != nil {
		prog.Close()
		return nil, fmt.Errorf("failed to attach program: %w", err)
	}

	return p, nil
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
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   p.program,
		Interface: p.spec.AttachTo,
	})
	if err != nil {
		return err
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
		return err
	}
	p.link = l
	return nil
}

// attachKretprobe 附加 kretprobe 程序
func (p *Program) attachKretprobe() error {
	l, err := link.Kretprobe(p.spec.AttachTo, p.program, nil)
	if err != nil {
		return err
	}
	p.link = l
	return nil
}

// attachTracepoint 附加 tracepoint 程序
func (p *Program) attachTracepoint() error {
	l, err := link.Tracepoint(link.TracepointOptions{
		Program: p.program,
		Group:   "net", // 假设是网络相关的 tracepoint
		Name:    p.spec.AttachTo,
	})
	if err != nil {
		return err
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
			lastErr = err
		}
	}

	// 关闭 maps
	for _, m := range p.maps {
		if err := m.Close(); err != nil {
			lastErr = err
		}
	}

	// 关闭程序
	if p.program != nil {
		if err := p.program.Close(); err != nil {
			lastErr = err
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

	// 这里应该使用 cilium/ebpf 的 LoadCollectionSpec 来加载
	// 现在先返回一个简单的规范作为占位符
	spec := &ebpf.ProgramSpec{
		Type:    ebpf.XDP,
		License: "GPL",
		// Instructions 应该从对象文件中读取
		Instructions: ebpf.Instructions{
			ebpf.Mov.Imm(ebpf.Reg0, 2), // XDP_PASS
			ebpf.Return(),
		},
	}

	return spec, nil
}
