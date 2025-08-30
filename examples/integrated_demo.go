package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Haibara-Ai97/netprobe/pkg/ebpf"
)

// 这个示例展示如何使用整合后的eBPF管理体系
// 演示XDP的三种工作模式：基础监控、安全过滤、负载均衡

func main() {
	// 检查eBPF支持
	if !ebpf.IsSupported() {
		log.Fatal("❌ eBPF is not supported on this system")
	}

	log.Println("🚀 NetProbe XDP Demo - Integrated eBPF Management System")
	log.Println("============================================================")

	// 使用默认配置创建管理器
	manager := ebpf.NewManager()
	defer manager.Close()

	// 加载eBPF程序
	if err := manager.LoadNetworkMonitor(); err != nil {
		log.Fatalf("❌ Failed to load eBPF programs: %v", err)
	}

	interfaceName := "ens33" // 根据实际环境调整

	// 演示1: 基础网络监控
	log.Println("\n📊 === Demo 1: Basic Network Monitoring ===")
	if err := manager.DemoBasicMonitoring(interfaceName, 10*time.Second); err != nil {
		log.Printf("⚠️  Basic monitoring demo failed: %v", err)
	}

	// 暂停一下
	time.Sleep(2 * time.Second)

	// 演示2: 高级安全过滤
	log.Println("\n🛡️  === Demo 2: Advanced Security Filtering ===")
	if err := manager.DemoSecurityFiltering(interfaceName, 10*time.Second); err != nil {
		log.Printf("⚠️  Security filtering demo failed: %v", err)
	}

	// 添加一些测试IP到黑名单
	testIPs := []string{"192.168.1.100", "10.0.0.50", "172.16.0.10"}
	log.Println("\n🔧 Adding test IPs to blacklist...")
	for _, ip := range testIPs {
		if err := manager.AddIPToBlacklist(ip); err != nil {
			log.Printf("⚠️  Failed to add %s: %v", ip, err)
		}
	}

	// 查看黑名单
	if blacklisted, err := manager.GetBlacklistedIPs(); err == nil {
		log.Printf("🚫 Current blacklist: %v", blacklisted)
	}

	// 暂停一下
	time.Sleep(2 * time.Second)

	// 演示3: 负载均衡
	log.Println("\n⚖️  === Demo 3: XDP Load Balancing ===")
	if err := manager.DemoLoadBalancing(interfaceName, 10*time.Second); err != nil {
		log.Printf("⚠️  Load balancing demo failed: %v", err)
	}

	// 最终统计报告
	log.Println("\n📊 === Final Statistics Report ===")
	printFinalReport(manager)

	// 清理黑名单
	log.Println("\n🧹 Cleaning up...")
	for _, ip := range testIPs {
		if err := manager.RemoveIPFromBlacklist(ip); err != nil {
			log.Printf("⚠️  Failed to remove %s: %v", ip, err)
		}
	}

	log.Println("✅ Demo completed successfully!")
}

func printFinalReport(manager *ebpf.Manager) {
	// 全局统计
	if stats, err := manager.GetGlobalStats(); err == nil {
		fmt.Printf("📈 Global Statistics:\n")
		fmt.Printf("   RX: %d packets, %s\n", stats.RxPackets, formatBytes(stats.RxBytes))
		fmt.Printf("   TX: %d packets, %s\n", stats.TxPackets, formatBytes(stats.TxBytes))
	}

	// Ring Buffer统计
	if rbStats := manager.GetRingBufferStats(); rbStats != nil {
		fmt.Printf("\n🔄 Ring Buffer Statistics:\n")
		fmt.Printf("   Events read: %d\n", rbStats["events_read"])
		fmt.Printf("   Events dropped: %d\n", rbStats["events_dropped"])
		fmt.Printf("   Batches processed: %d\n", rbStats["batches_processed"])
	}

	// 安全统计
	if secStats, err := manager.GetSecurityStats(); err == nil {
		fmt.Printf("\n🛡️  Security Statistics:\n")
		fmt.Printf("   DDoS attacks blocked: %d\n", secStats.DDosBlocked)
		fmt.Printf("   Security events: %d\n", secStats.SecurityEvents)
		fmt.Printf("   XDP packets dropped: %d\n", secStats.XDPDropped)
		fmt.Printf("   Blacklisted IPs: %d\n", secStats.BlacklistedIPs)
	}

	// 负载均衡统计
	if lbStats, err := manager.GetLoadBalancerStats(); err == nil {
		fmt.Printf("\n⚖️  Load Balancer Statistics:\n")
		fmt.Printf("   Total decisions: %d\n", lbStats.LBDecisions)
		for target, count := range lbStats.TargetCounts {
			if lbStats.LBDecisions > 0 {
				percentage := float64(count) / float64(lbStats.LBDecisions) * 100
				fmt.Printf("   Target %d: %d packets (%.1f%%)\n", target, count, percentage)
			}
		}
	}

	// 流统计概要
	if flowStats, err := manager.GetFlowStats(); err == nil {
		fmt.Printf("\n🌊 Flow Statistics:\n")
		fmt.Printf("   Total active flows: %d\n", len(flowStats))
	}

	// TC设备统计
	if tcStats, err := manager.GetTCDeviceStats(); err == nil && len(tcStats) > 0 {
		fmt.Printf("\n📡 TC Device Statistics:\n")
		for key, value := range tcStats {
			direction := "ingress"
			if key.Direction == 1 {
				direction = "egress"
			}
			statType := "packets"
			if key.StatType == 1 {
				statType = "bytes"
			}
			fmt.Printf("   Interface %d %s %s: %d\n", key.Ifindex, direction, statType, value)
		}
	}
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
