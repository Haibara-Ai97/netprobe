package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
	// 检查是否为 root 用户
	if os.Geteuid() != 0 {
		log.Fatal("This program requires root privileges")
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("🚀 Starting KubeNetProbe eBPF Monitor with Cilium/eBPF...")

	// 使用 Cilium/eBPF 实现
	if err := runCiliumImplementation(ctx); err != nil {
		log.Fatal(err)
	}

	// 等待信号
	<-sigCh
	fmt.Println("\n🛑 Shutting down...")
	cancel()
}

// runCiliumImplementation 运行 cilium/ebpf 实现
func runCiliumImplementation(ctx context.Context) error {
	fmt.Println("📡 Using cilium/ebpf implementation")

	monitor, err := ebpf.NewNetworkMonitor()
	if err != nil {
		return fmt.Errorf("creating network monitor: %w", err)
	}
	defer monitor.Close()

	// 获取网络接口名称
	ifaceName := getNetworkInterface()
	fmt.Printf("🔗 Attaching to interface: %s\n", ifaceName)

	// 附加到网络接口
	if err := monitor.AttachToInterface(ifaceName); err != nil {
		return fmt.Errorf("attaching to interface: %w", err)
	}

	// 启动事件处理
	if err := monitor.StartEventProcessing(); err != nil {
		return fmt.Errorf("starting event processing: %w", err)
	}

	// 设置安全配置
	if err := monitor.SetSecurityConfig(0, 10); err != nil { // 端口扫描阈值 = 10
		fmt.Printf("⚠️  Warning: failed to set security config: %v\n", err)
	}

	// 定期打印统计信息
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := printStats(monitor); err != nil {
				fmt.Printf("❌ Error getting stats: %v\n", err)
			}
		}
	}
}

// runObjectLoaderImplementation 运行对象文件加载实现
func runObjectLoaderImplementation(ctx context.Context) error {
	fmt.Println("📁 Using object file loader implementation")

	loader := ebpf.NewEBPFLoader()
	defer loader.Close()

	// 加载网络监控程序
	if err := loader.LoadFromObjectFile("./bin/ebpf/network-monitor.o"); err != nil {
		return fmt.Errorf("loading network monitor: %w", err)
	}

	ifaceName := getNetworkInterface()
	if err := loader.AttachXDP("network_monitor_xdp", ifaceName); err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}

	// 加载安全监控程序
	securityLoader := ebpf.NewEBPFLoader()
	defer securityLoader.Close()

	if err := securityLoader.LoadFromObjectFile("./bin/ebpf/security-monitor.o"); err != nil {
		fmt.Printf("⚠️  Warning: failed to load security monitor: %v\n", err)
	} else {
		if err := securityLoader.AttachKprobe("trace_tcp_connect", "tcp_v4_connect"); err != nil {
			fmt.Printf("⚠️  Warning: failed to attach kprobe: %v\n", err)
		}
	}

	fmt.Println("✅ Programs loaded and attached successfully")

	// 定期读取统计
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := printObjectLoaderStats(loader); err != nil {
				fmt.Printf("❌ Error getting stats: %v\n", err)
			}
		}
	}
}

// runEmbeddedImplementation 运行嵌入式实现
func runEmbeddedImplementation(ctx context.Context) error {
	fmt.Println("📦 Using embedded implementation")

	loader := ebpf.NewEmbeddedLoader()
	defer loader.Close()

	if err := loader.LoadEmbeddedPrograms(); err != nil {
		return fmt.Errorf("loading embedded programs: %w", err)
	}

	ifaceName := getNetworkInterface()
	if err := loader.AttachNetworkPrograms(ifaceName); err != nil {
		return fmt.Errorf("attaching network programs: %w", err)
	}

	if err := loader.AttachSecurityPrograms(); err != nil {
		fmt.Printf("⚠️  Warning: failed to attach security programs: %v\n", err)
	}

	fmt.Println("✅ Embedded programs loaded successfully")

	// 保持运行
	<-ctx.Done()
	return nil
}

// runLibbpfGoImplementation 运行 libbpfgo 实现
func runLibbpfGoImplementation(ctx context.Context) error {
	fmt.Println("🔧 Using libbpfgo implementation")

	monitor := ebpf.NewLibbpfGoMonitor()
	defer monitor.Close()

	if err := monitor.LoadFromObjectFile("./bin/ebpf/network-monitor.o"); err != nil {
		return fmt.Errorf("loading programs: %w", err)
	}

	ifaceName := getNetworkInterface()
	if err := monitor.AttachXDP("network_monitor_xdp", ifaceName); err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}

	if err := monitor.AttachKprobe("trace_tcp_connect", "tcp_v4_connect"); err != nil {
		fmt.Printf("⚠️  Warning: failed to attach kprobe: %v\n", err)
	}

	// 设置事件处理器
	if err := monitor.SetRingbufHandler("packet_events", handlePacketEvent); err != nil {
		fmt.Printf("⚠️  Warning: failed to set event handler: %v\n", err)
	}

	fmt.Println("✅ libbpfgo programs loaded successfully")

	// 定期读取统计
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if stats, err := monitor.GetMapStats("packet_stats"); err == nil {
				printLibbpfGoStats(stats)
			}
		}
	}
}

// printStats 打印 cilium/ebpf 统计信息
func printStats(monitor *ebpf.NetworkMonitor) error {
	packetStats, err := monitor.GetPacketStats()
	if err != nil {
		return err
	}

	flowStats, err := monitor.GetFlowStats()
	if err != nil {
		return err
	}

	fmt.Println("📊 Network Statistics:")
	fmt.Printf("  📥 RX: %d packets, %d bytes\n",
		packetStats["rx_packets"], packetStats["rx_bytes"])
	fmt.Printf("  📤 TX: %d packets, %d bytes\n",
		packetStats["tx_packets"], packetStats["tx_bytes"])
	fmt.Printf("  🌊 Active flows: %d\n", len(flowStats))

	if len(flowStats) > 0 && len(flowStats) <= 5 {
		fmt.Println("  🔝 Top flows:")
		for flow, count := range flowStats {
			fmt.Printf("    %s: %d packets\n", flow, count)
		}
	}

	return nil
}

// printObjectLoaderStats 打印对象加载器统计信息
func printObjectLoaderStats(loader *ebpf.EBPFLoader) error {
	statsMap, err := loader.GetMap("packet_stats")
	if err != nil {
		return err
	}

	var rxPackets, txPackets, rxBytes, txBytes uint64

	// 读取各项统计
	statsMap.Lookup(uint32(0), &rxPackets)
	statsMap.Lookup(uint32(1), &txPackets)
	statsMap.Lookup(uint32(2), &rxBytes)
	statsMap.Lookup(uint32(3), &txBytes)

	fmt.Println("📊 Network Statistics:")
	fmt.Printf("  📥 RX: %d packets, %d bytes\n", rxPackets, rxBytes)
	fmt.Printf("  📤 TX: %d packets, %d bytes\n", txPackets, txBytes)

	return nil
}

// printLibbpfGoStats 打印 libbpfgo 统计信息
func printLibbpfGoStats(stats map[string]uint64) {
	fmt.Println("📊 Network Statistics:")
	fmt.Printf("  📥 RX: %d packets, %d bytes\n",
		stats["rx_packets"], stats["rx_bytes"])
	fmt.Printf("  📤 TX: %d packets, %d bytes\n",
		stats["tx_packets"], stats["tx_bytes"])
}

// handlePacketEvent 处理数据包事件
func handlePacketEvent(data []byte) {
	fmt.Printf("📦 Packet event: %d bytes\n", len(data))
}

// getNetworkInterface 获取网络接口名称
func getNetworkInterface() string {
	// 优先级：环境变量 > eth0 > 第一个非回环接口
	if iface := os.Getenv("NETWORK_INTERFACE"); iface != "" {
		return iface
	}

	// 检查是否存在 eth0
	if _, err := net.InterfaceByName("eth0"); err == nil {
		return "eth0"
	}

	// 查找第一个非回环接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return "lo" // 回退到回环接口
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}

	return "lo"
}
