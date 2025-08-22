package main

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	"log"
	"os"
	"os/signal"
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

	// 创建嵌入式加载器
	loader := ebpfc.NewEmbeddedLoader()
	defer loader.Close()

	// 加载嵌入的程序
	if err := loader.LoadEmbeddedPrograms(); err != nil {
		log.Fatalf("Failed to load eBPF programs: %v", err)
	}

	// 附加网络监控程序
	if err := loader.AttachNetworkPrograms(interfaceName); err != nil {
		log.Fatalf("Failed to attach network programs: %v", err)
	}

	fmt.Printf("✅ TC monitoring started on interface %s\n", interfaceName)
	fmt.Println("📊 Monitoring TC traffic statistics...")
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

func showStatistics(ctx context.Context, loader *ebpfc.EmbeddedLoader) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printTCStatistics(loader)
		}
	}
}

func printTCStatistics(loader *ebpfc.EmbeddedLoader) {
	// 获取全局统计信息
	statsMap, err := loader.GetNetworkMap("packet_stats")
	if err != nil {
		log.Printf("Failed to get stats map: %v", err)
		return
	}

	// 获取 TC 设备统计
	tcStatsMap, err := loader.GetNetworkMap("tc_device_stats")
	if err != nil {
		log.Printf("Failed to get TC stats map: %v", err)
		return
	}

	fmt.Println("\n📈 Traffic Statistics:")
	//fmt.Println("=" * 50)

	// 打印全局统计
	printGlobalStats(statsMap)

	// 打印 TC 设备统计
	printTCDeviceStats(tcStatsMap)

	//fmt.Println("=" * 50)
}

func printGlobalStats(statsMap *ebpf.Map) {
	stats := []struct {
		key  uint32
		name string
	}{
		{0, "RX Packets"},
		{1, "TX Packets"},
		{2, "RX Bytes"},
		{3, "TX Bytes"},
	}

	fmt.Println("Global Statistics:")
	for _, stat := range stats {
		var value uint64
		if err := statsMap.Lookup(&stat.key, &value); err == nil {
			if stat.key >= 2 { // bytes
				fmt.Printf("  %-12s: %s\n", stat.name, formatBytes(value))
			} else { // packets
				fmt.Printf("  %-12s: %d\n", stat.name, value)
			}
		}
	}
}

func printTCDeviceStats(tcStatsMap *ebpf.Map) {
	fmt.Println("\nTC Device Statistics:")

	// 这里需要遍历 TC 统计 Map
	// 由于 Map 遍历在 Go 中比较复杂，这里展示概念
	fmt.Println("  (TC device stats would be displayed here)")
	fmt.Println("  - Per-device ingress/egress packet counts")
	fmt.Println("  - Per-device ingress/egress byte counts")
	fmt.Println("  - Queue mapping statistics")
	fmt.Println("  - Traffic classification results")
}

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
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
