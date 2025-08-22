package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// EBPFLoader 从预编译对象文件加载 eBPF 程序
type EBPFLoader struct {
	spec  *ebpf.CollectionSpec
	coll  *ebpf.Collection
	links []link.Link
}

// NewEBPFLoader 创建新的加载器
func NewEBPFLoader() *EBPFLoader {
	return &EBPFLoader{}
}

// LoadFromObjectFile 从对象文件加载 eBPF 程序
func (el *EBPFLoader) LoadFromObjectFile(objectPath string) error {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// 读取对象文件
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("loading collection spec: %w", err)
	}
	el.spec = spec

	// 创建 Collection
	el.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("creating collection: %w", err)
	}

	return nil
}

// AttachXDP 附加 XDP 程序
func (el *EBPFLoader) AttachXDP(progName, interfaceName string) error {
	prog := el.coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("program %s not found", progName)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("finding interface: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}

	el.links = append(el.links, l)
	return nil
}

// AttachKprobe 附加 Kprobe 程序
func (el *EBPFLoader) AttachKprobe(progName, symbolName string) error {
	prog := el.coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("program %s not found", progName)
	}

	l, err := link.Kprobe(symbolName, prog, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}

	el.links = append(el.links, l)
	return nil
}

// GetMap 获取指定的 Map
func (el *EBPFLoader) GetMap(mapName string) (*ebpf.Map, error) {
	m := el.coll.Maps[mapName]
	if m == nil {
		return nil, fmt.Errorf("map %s not found", mapName)
	}
	return m, nil
}

// Close 关闭加载器
func (el *EBPFLoader) Close() error {
	var lastErr error

	// 关闭所有 links
	for _, l := range el.links {
		if err := l.Close(); err != nil {
			lastErr = err
		}
	}

	// 关闭 collection
	el.coll.Close()

	return lastErr
}

// 使用示例
func ExampleUsage() error {
	loader := NewEBPFLoader()
	defer loader.Close()

	// 从预编译的对象文件加载
	if err := loader.LoadFromObjectFile("./bin/ebpf/network-monitor.o"); err != nil {
		return err
	}

	// 附加 XDP 程序
	if err := loader.AttachXDP("network_monitor_xdp", "eth0"); err != nil {
		return err
	}

	// 附加 Kprobe 程序
	if err := loader.AttachKprobe("trace_tcp_connect", "tcp_v4_connect"); err != nil {
		return err
	}

	// 获取统计 Map
	statsMap, err := loader.GetMap("packet_stats")
	if err != nil {
		return err
	}

	// 读取统计数据
	var rxPackets uint64
	key := uint32(0) // STAT_RX_PACKETS
	if err := statsMap.Lookup(key, &rxPackets); err != nil {
		return err
	}

	fmt.Printf("RX Packets: %d\n", rxPackets)
	return nil
}
