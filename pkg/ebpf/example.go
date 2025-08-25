package ebpf

import (
	"fmt"
	"time"
)

// Example 展示如何使用 NetworkLoader
func ExampleNetworkLoader() error {
	// 创建网络加载器
	loader := NewNetworkLoader()
	defer loader.Close()

	// 加载 eBPF 程序
	fmt.Println("🚀 Loading eBPF programs...")
	if err := loader.LoadPrograms(); err != nil {
		return fmt.Errorf("failed to load programs: %w", err)
	}

	// 附加到网络接口（例如 eth0 或 lo）
	interfaceName := "lo" // 使用回环接口作为示例
	fmt.Printf("🔗 Attaching to interface: %s\n", interfaceName)
	if err := loader.AttachNetworkPrograms(interfaceName); err != nil {
		return fmt.Errorf("failed to attach programs: %w", err)
	}

	// 监控统计信息
	fmt.Println("📊 Monitoring network statistics for 10 seconds...")
	for i := 0; i < 10; i++ {
		stats, err := loader.ReadGlobalStats()
		if err != nil {
			fmt.Printf("❌ Error reading stats: %v\n", err)
			continue
		}

		fmt.Printf("⏱️  [%ds] %s\n", i+1, stats.String())
		time.Sleep(1 * time.Second)
	}

	// 读取流量统计
	flowStats, err := loader.ReadFlowStats()
	if err != nil {
		fmt.Printf("⚠️  Failed to read flow stats: %v\n", err)
	} else {
		fmt.Printf("📈 Flow statistics: %d entries\n", len(flowStats))
		for flow, count := range flowStats {
			if count > 0 {
				fmt.Printf("   %+v: %d packets\n", flow, count)
			}
		}
	}

	// 读取 TC 设备统计
	tcStats, err := loader.ReadTCDeviceStats()
	if err != nil {
		fmt.Printf("⚠️  Failed to read TC stats: %v\n", err)
	} else {
		fmt.Printf("🚦 TC device statistics: %d entries\n", len(tcStats))
		for key, value := range tcStats {
			if value > 0 {
				fmt.Printf("   Interface %d, Direction %d, Type %d: %d\n",
					key.Ifindex, key.Direction, key.StatType, value)
			}
		}
	}

	fmt.Println("✅ Example completed successfully")
	return nil
}

// ExampleManagerUsage 展示如何使用 Manager
func ExampleManagerUsage() error {
	// 创建管理器
	manager := NewManager()
	defer manager.Close()

	// 检查 eBPF 支持
	if !IsSupported() {
		return fmt.Errorf("eBPF is not supported on this system")
	}

	// 加载网络监控程序
	fmt.Println("🚀 Loading network monitor...")
	if err := manager.LoadNetworkMonitor(); err != nil {
		return fmt.Errorf("failed to load network monitor: %w", err)
	}

	// 附加到网络接口
	interfaceName := "lo"
	fmt.Printf("🔗 Attaching network monitor to %s\n", interfaceName)
	if err := manager.AttachNetworkMonitor(interfaceName); err != nil {
		return fmt.Errorf("failed to attach network monitor: %w", err)
	}

	// 获取统计信息
	fmt.Println("📊 Reading network statistics...")
	stats, err := manager.GetNetworkStats()
	if err != nil {
		return fmt.Errorf("failed to get network stats: %w", err)
	}

	for name, value := range stats {
		fmt.Printf("   %s: %d\n", name, value)
	}

	fmt.Println("✅ Manager example completed successfully")
	return nil
}
