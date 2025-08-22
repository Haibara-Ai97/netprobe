package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// 嵌入预编译的 eBPF 对象文件
//
//go:embed objects/network-monitor.o
var networkMonitorObj []byte

//go:embed objects/security-monitor.o
var securityMonitorObj []byte

// EmbeddedLoader 使用嵌入字节码的加载器
type EmbeddedLoader struct {
	networkColl  *ebpf.Collection
	securityColl *ebpf.Collection
	links        []link.Link
}

// NewEmbeddedLoader 创建嵌入式加载器
func NewEmbeddedLoader() *EmbeddedLoader {
	return &EmbeddedLoader{}
}

// LoadEmbeddedPrograms 加载嵌入的程序
func (el *EmbeddedLoader) LoadEmbeddedPrograms() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// 加载网络监控程序
	networkSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(networkMonitorObj))
	if err != nil {
		return fmt.Errorf("loading network spec: %w", err)
	}

	el.networkColl, err = ebpf.NewCollection(networkSpec)
	if err != nil {
		return fmt.Errorf("creating network collection: %w", err)
	}

	// 加载安全监控程序
	securitySpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(securityMonitorObj))
	if err != nil {
		return fmt.Errorf("loading security spec: %w", err)
	}

	el.securityColl, err = ebpf.NewCollection(securitySpec)
	if err != nil {
		return fmt.Errorf("creating security collection: %w", err)
	}

	return nil
}

// AttachNetworkPrograms 附加网络监控程序
func (el *EmbeddedLoader) AttachNetworkPrograms(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("finding interface: %w", err)
	}

	// 附加 XDP 程序
	xdpProg := el.networkColl.Programs["network_monitor_xdp"]
	if xdpProg != nil {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   xdpProg,
			Interface: iface.Index,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP: %w", err)
		}
		el.links = append(el.links, l)
	}

	// 附加 TC 程序
	tcEgressProg := el.networkColl.Programs["network_monitor_tc_egress"]
	if tcEgressProg != nil {
		// TC 程序需要更复杂的附加逻辑
		// 这里简化处理
		fmt.Println("⚠️  TC egress program loaded but not attached (requires tc command)")
	}

	// 附加 TC 入口程序
	tcIngressProg := el.networkColl.Programs["network_monitor_tc_ingress"]
	if tcIngressProg != nil {
		// TC 程序需要更复杂的附加逻辑
		// 这里简化处理
		fmt.Println("⚠️  TC ingress program loaded but not attached (requires tc command)")
	}

	return nil
}

// AttachSecurityPrograms 附加安全监控程序
func (el *EmbeddedLoader) AttachSecurityPrograms() error {
	// 附加 TCP 连接监控 kprobe
	tcpProg := el.securityColl.Programs["trace_tcp_connect"]
	if tcpProg != nil {
		l, err := link.Kprobe("tcp_v4_connect", tcpProg, nil)
		if err != nil {
			return fmt.Errorf("attaching tcp kprobe: %w", err)
		}
		el.links = append(el.links, l)
	}

	// 附加其他安全监控程序...

	return nil
}

// GetNetworkMap 获取网络监控 Map
func (el *EmbeddedLoader) GetNetworkMap(mapName string) (*ebpf.Map, error) {
	m := el.networkColl.Maps[mapName]
	if m == nil {
		return nil, fmt.Errorf("network map %s not found", mapName)
	}
	return m, nil
}

// GetSecurityMap 获取安全监控 Map
func (el *EmbeddedLoader) GetSecurityMap(mapName string) (*ebpf.Map, error) {
	m := el.securityColl.Maps[mapName]
	if m == nil {
		return nil, fmt.Errorf("security map %s not found", mapName)
	}
	return m, nil
}

// Close 关闭加载器
func (el *EmbeddedLoader) Close() error {
	var lastErr error

	for _, l := range el.links {
		if err := l.Close(); err != nil {
			lastErr = err
		}
	}

	if el.networkColl != nil {
		el.networkColl.Close()
	}

	if el.securityColl != nil {
		el.securityColl.Close()
	}

	return lastErr
}
