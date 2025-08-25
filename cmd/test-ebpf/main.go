package main

import (
	"fmt"
	"log"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
	fmt.Println("🚀 NetProbe eBPF Test")

	// 检查 eBPF 支持
	if !ebpf.IsSupported() {
		log.Fatal("❌ eBPF is not supported on this system")
	}
	fmt.Println("✅ eBPF is supported")

	// 创建管理器
	manager := ebpf.NewManager()
	defer manager.Close()

	// 加载网络监控程序
	fmt.Println("📦 Loading network monitor...")
	if err := manager.LoadNetworkMonitor(); err != nil {
		log.Fatalf("❌ Failed to load network monitor: %v", err)
	}
	fmt.Println("✅ Network monitor loaded successfully")

	// 尝试附加到回环接口
	fmt.Println("🔗 Attaching to loopback interface...")
	if err := manager.AttachNetworkMonitor("lo"); err != nil {
		log.Printf("⚠️  Warning: Failed to attach to loopback: %v", err)
		fmt.Println("💡 This is normal if not running as root")
	} else {
		fmt.Println("✅ Successfully attached to loopback interface")
	}

	// 获取统计信息
	fmt.Println("📊 Reading network statistics...")
	stats, err := manager.GetNetworkStats()
	if err != nil {
		log.Printf("⚠️  Warning: Failed to read stats: %v", err)
	} else {
		fmt.Println("📈 Network Statistics:")
		for name, value := range stats {
			fmt.Printf("   %s: %d\n", name, value)
		}
	}

	fmt.Println("🎉 Test completed successfully!")
}
