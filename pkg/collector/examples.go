package collector

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

// Example 演示如何使用 TC 收集器
func Example() {
	// 1. 创建 eBPF 管理器
	ebpfManager := ebpf.NewManager()

	// 2. 加载网络监控程序
	if err := ebpfManager.LoadNetworkMonitor(); err != nil {
		log.Fatalf("Failed to load network monitor: %v", err)
	}
	defer ebpfManager.Close()

	// 3. 创建收集器管理器
	collectorManager := NewManager(ebpfManager)

	// 4. 设置收集间隔为 3 秒
	collectorManager.SetCollectInterval(3 * time.Second)

	// 5. 启动收集器
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resultChan := collectorManager.Start(ctx)
	if resultChan == nil {
		log.Fatalf("Failed to start collection manager")
	}

	fmt.Println("🚀 Starting TC traffic collection...")
	fmt.Println("📊 Collecting network interface statistics every 3 seconds...")

	// 6. 处理收集结果
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				fmt.Println("✅ Collection completed")
				return
			}

			if result.Error != nil {
				log.Printf("❌ Collection error: %v", result.Error)
				continue
			}

			// 显示收集结果
			fmt.Printf("\n📈 Collection at %s:\n", result.Timestamp.Format("15:04:05"))
			
			if len(result.Stats) == 0 {
				fmt.Println("   No interface statistics available")
				continue
			}

			// 创建摘要
			summary := SummarizeCollection(result.Stats, 5)
			fmt.Println(summary.String())

			// 显示活跃接口的详细信息
			activeStats := FilterActiveInterfaces(result.Stats)
			if len(activeStats) > 0 {
				fmt.Println("\n🔥 Active Interfaces:")
				for _, stat := range activeStats {
					fmt.Printf("   %s\n", stat.Summary())
				}
			}

		case <-ctx.Done():
			fmt.Println("⏰ Collection timeout reached")
			return
		}
	}
}

// QuickTest 快速测试收集器功能
func QuickTest(ebpfManager *ebpf.Manager) error {
	// 创建 TC 收集器
	tcCollector := NewTCCollector(ebpfManager)

	fmt.Println("🔍 Testing TC collector...")

	// 执行一次收集
	stats, err := tcCollector.CollectOnce()
	if err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	fmt.Printf("✅ Successfully collected stats for %d interfaces\n", len(stats))

	// 显示接口信息
	interfaces := tcCollector.GetSupportedInterfaces()
	fmt.Printf("📡 Available interfaces: %v\n", interfaces)

	// 显示收集到的统计信息
	if len(stats) > 0 {
		fmt.Println("\n📊 Interface Statistics:")
		for _, stat := range stats {
			if stat.HasTraffic() {
				fmt.Printf("   %s: %d/%d packets (in/out), %s/%s bytes\n",
					stat.InterfaceName,
					stat.IngressPackets, stat.EgressPackets,
					FormatBytes(stat.IngressBytes), FormatBytes(stat.EgressBytes))
			}
		}
	} else {
		fmt.Println("ℹ️  No traffic statistics available yet")
	}

	return nil
}

// MonitorInterface 监控特定接口
func MonitorInterface(ebpfManager *ebpf.Manager, interfaceName string, duration time.Duration) {
	collectorManager := NewManager(ebpfManager)
	collectorManager.SetCollectInterval(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	resultChan := collectorManager.Start(ctx)
	if resultChan == nil {
		log.Printf("Failed to start monitoring for interface %s", interfaceName)
		return
	}

	fmt.Printf("🎯 Monitoring interface '%s' for %v...\n", interfaceName, duration)

	var lastStats *InterfaceStats
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				fmt.Println("✅ Monitoring completed")
				return
			}

			if result.Error != nil {
				log.Printf("❌ Monitoring error: %v", result.Error)
				continue
			}

			// 查找目标接口
			for _, stat := range result.Stats {
				if stat.InterfaceName == interfaceName {
					fmt.Printf("[%s] %s | ",
						result.Timestamp.Format("15:04:05"),
						stat.Summary())

					// 显示与上次的差异
					if lastStats != nil {
						inDiff := int64(stat.IngressPackets - lastStats.IngressPackets)
						outDiff := int64(stat.EgressPackets - lastStats.EgressPackets)
						fmt.Printf("Δ %+d/%+d pkts", inDiff, outDiff)
					}
					fmt.Println()

					// 保存当前统计作为下次比较的基准
					currentStat := stat
					lastStats = &currentStat
					break
				}
			}

		case <-ctx.Done():
			fmt.Println("⏰ Monitoring timeout reached")
			return
		}
	}
}
