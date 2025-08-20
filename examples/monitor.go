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
	fmt.Println("📡 Using cilium/eBPF implementation")

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

// printStats 打印 cilium/eBPF 统计信息
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
