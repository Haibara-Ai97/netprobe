package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ebpfc "github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: tc_monitor_example <interface_name>")
		os.Exit(1)
	}

	interfaceName := os.Args[1]

	// 验证网络接口是否存在
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		log.Fatalf("Interface %s not found: %v", interfaceName, err)
	}

	// 创建 bpf2go 加载器
	loader := ebpfc.NewBpf2goLoader()
	defer loader.Close()

	// 加载 eBPF 程序
	fmt.Println("🔄 Loading eBPF programs...")
	if err := loader.LoadPrograms(); err != nil {
		log.Fatalf("Failed to load eBPF programs: %v", err)
	}

	// 附加网络监控程序
	fmt.Println("🔗 Attaching network programs...")
	if err := loader.AttachNetworkPrograms(interfaceName); err != nil {
		log.Fatalf("Failed to attach network programs: %v", err)
	}

	fmt.Printf("✅ TC monitoring started on interface %s\n", interfaceName)
	fmt.Println("📊 Monitoring network traffic statistics...")
	fmt.Println("Press Ctrl+C to stop")

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动统计显示协程
	go showStatistics(ctx, loader)

	// 等待中断信号
	<-sigChan
	fmt.Println("\n🛑 Shutting down...")
}

func showStatistics(ctx context.Context, loader *ebpfc.Bpf2goLoader) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	fmt.Println("\n📊 Starting statistics monitoring...")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printStatistics(loader)
		}
	}
}

func printStatistics(loader *ebpfc.Bpf2goLoader) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("📈 Traffic Statistics [%s]\n", time.Now().Format("15:04:05"))
	fmt.Println(strings.Repeat("=", 60))

	// 打印全局统计
	if err := printGlobalStats(loader); err != nil {
		log.Printf("❌ Failed to get global stats: %v", err)
	}

	// 打印 TC 设备统计
	if err := printTCDeviceStats(loader); err != nil {
		log.Printf("❌ Failed to get TC device stats: %v", err)
	}

	// 打印流量统计（前10个）
	if err := printTopFlowStats(loader); err != nil {
		log.Printf("❌ Failed to get flow stats: %v", err)
	}
}

func printGlobalStats(loader *ebpfc.Bpf2goLoader) error {
	stats, err := loader.ReadGlobalStats()
	if err != nil {
		return err
	}

	fmt.Println("\n🌐 Global Statistics:")
	fmt.Printf("  📥 RX: %s packets, %s\n",
		formatNumber(stats.RxPackets),
		formatBytes(stats.RxBytes))
	fmt.Printf("  📤 TX: %s packets, %s\n",
		formatNumber(stats.TxPackets),
		formatBytes(stats.TxBytes))

	// 计算总流量
	totalPackets := stats.RxPackets + stats.TxPackets
	totalBytes := stats.RxBytes + stats.TxBytes
	fmt.Printf("  📊 Total: %s packets, %s\n",
		formatNumber(totalPackets),
		formatBytes(totalBytes))

	// 计算平均包大小
	if totalPackets > 0 {
		avgSize := totalBytes / totalPackets
		fmt.Printf("  📏 Average packet size: %d bytes\n", avgSize)
	}

	return nil
}

func printTCDeviceStats(loader *ebpfc.Bpf2goLoader) error {
	tcStats, err := loader.ReadTCDeviceStats()
	if err != nil {
		return err
	}

	fmt.Println("\n🔀 TC Device Statistics:")

	if len(tcStats) == 0 {
		fmt.Println("  (No TC device statistics available yet)")
		return nil
	}

	// 按设备索引分组统计
	deviceStats := make(map[uint32]map[string]uint64)

	for key, value := range tcStats {
		if deviceStats[key.Ifindex] == nil {
			deviceStats[key.Ifindex] = make(map[string]uint64)
		}

		direction := "ingress"
		if key.Direction == 1 {
			direction = "egress"
		}

		statType := "packets"
		if key.StatType == 1 {
			statType = "bytes"
		}

		statKey := fmt.Sprintf("%s_%s", direction, statType)
		deviceStats[key.Ifindex][statKey] = value
	}

	// 显示每个设备的统计
	for ifindex, stats := range deviceStats {
		fmt.Printf("  📡 Interface %d:\n", ifindex)
		fmt.Printf("    📥 Ingress: %s packets, %s\n",
			formatNumber(stats["ingress_packets"]),
			formatBytes(stats["ingress_bytes"]))
		fmt.Printf("    📤 Egress:  %s packets, %s\n",
			formatNumber(stats["egress_packets"]),
			formatBytes(stats["egress_bytes"]))
	}

	return nil
}

func printTopFlowStats(loader *ebpfc.Bpf2goLoader) error {
	flowStats, err := loader.ReadFlowStats()
	if err != nil {
		return err
	}

	fmt.Println("\n🌊 Top Flow Statistics:")

	if len(flowStats) == 0 {
		fmt.Println("  (No flow statistics available yet)")
		return nil
	}

	// 找出前10个最活跃的流量
	type flowStat struct {
		key   ebpfc.FlowKey
		count uint64
	}

	var topFlows []flowStat
	for key, count := range flowStats {
		topFlows = append(topFlows, flowStat{key, count})
		if len(topFlows) >= 10 {
			break
		}
	}

	// 简单排序（按包数量降序）
	for i := 0; i < len(topFlows)-1; i++ {
		for j := i + 1; j < len(topFlows); j++ {
			if topFlows[j].count > topFlows[i].count {
				topFlows[i], topFlows[j] = topFlows[j], topFlows[i]
			}
		}
	}

	// 显示前5个流量
	maxDisplay := 5
	if len(topFlows) < maxDisplay {
		maxDisplay = len(topFlows)
	}

	for i := 0; i < maxDisplay; i++ {
		flow := topFlows[i]
		protocol := "Other"
		switch flow.key.Protocol {
		case 6:
			protocol = "TCP"
		case 17:
			protocol = "UDP"
		case 1:
			protocol = "ICMP"
		}

		fmt.Printf("  %d. %s %s:%d -> %s:%d (%s packets)\n",
			i+1,
			protocol,
			ipToString(flow.key.SrcIP), flow.key.SrcPort,
			ipToString(flow.key.DstIP), flow.key.DstPort,
			formatNumber(flow.count))
	}

	return nil
}

// 辅助函数：格式化数字
func formatNumber(n uint64) string {
	if n >= 1000000000 {
		return fmt.Sprintf("%.2fG", float64(n)/1000000000)
	} else if n >= 1000000 {
		return fmt.Sprintf("%.2fM", float64(n)/1000000)
	} else if n >= 1000 {
		return fmt.Sprintf("%.2fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

// 辅助函数：格式化字节数
func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// 辅助函数：将 IP 地址从 uint32 转换为字符串
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF,
		(ip>>8)&0xFF,
		(ip>>16)&0xFF,
		(ip>>24)&0xFF)
}
