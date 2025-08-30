package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Haibara-Ai97/netprobe/pkg/ebpf"
)

func main() {
	var (
		iface    = flag.String("interface", "lo", "Network interface to monitor")
		mode     = flag.String("mode", "basic", "XDP mode: basic, security, loadbalancer")
		duration = flag.Duration("duration", 0, "Demo duration (0 for continuous)")
		demo     = flag.Bool("demo", false, "Run demonstration mode")
		reset    = flag.Bool("reset", false, "Reset all statistics")
	)
	flag.Parse()

	// Check if eBPF is supported
	if !ebpf.IsSupported() {
		log.Fatal("❌ eBPF is not supported on this system")
	}

	// Create manager with custom configuration
	config := ebpf.DefaultManagerConfig()

	// Parse XDP mode
	switch *mode {
	case "basic":
		config.XDPMode = ebpf.XDPBasicMonitor
		config.EnableXDPEvents = false
	case "security":
		config.XDPMode = ebpf.XDPAdvancedFilter
		config.EnableXDPEvents = true
		config.EnableDetailedEvents = true
	case "loadbalancer", "lb":
		config.XDPMode = ebpf.XDPLoadBalancer
		config.EnableXDPEvents = true
	default:
		log.Fatalf("❌ Unknown mode: %s (use: basic, security, loadbalancer)", *mode)
	}

	manager := ebpf.NewManagerWithConfig(config)
	defer manager.Close()

	// Load eBPF programs
	if err := manager.LoadNetworkMonitor(); err != nil {
		log.Fatalf("❌ Failed to load eBPF programs: %v", err)
	}

	if *reset {
		log.Println("🔄 Resetting all statistics...")
		if err := manager.ResetStatistics(); err != nil {
			log.Printf("⚠️  Failed to reset statistics: %v", err)
		} else {
			log.Println("✅ Statistics reset successfully")
		}
		return
	}

	if *demo {
		runDemoMode(manager, *iface, *mode, *duration)
		return
	}

	// Start monitoring
	if err := manager.AttachNetworkMonitor(*iface); err != nil {
		log.Fatalf("❌ Failed to attach to interface %s: %v", *iface, err)
	}

	log.Printf("🎯 Monitoring %s with %s mode", *iface, config.XDPMode)

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start statistics reporter
	go statisticsReporter(ctx, manager)

	// Wait for signal or duration
	if *duration > 0 {
		timer := time.NewTimer(*duration)
		select {
		case <-timer.C:
			log.Printf("⏰ Duration %v completed", *duration)
		case <-sigChan:
			log.Println("📡 Received interrupt signal")
		}
	} else {
		<-sigChan
		log.Println("📡 Received interrupt signal")
	}

	// Print final statistics
	printFinalStats(manager)
}

func runDemoMode(manager *ebpf.Manager, iface, mode string, duration time.Duration) {
	demoDuration := duration
	if demoDuration == 0 {
		demoDuration = 30 * time.Second
	}

	log.Printf("🎬 Running demonstration mode for %v", demoDuration)

	switch mode {
	case "basic":
		if err := manager.DemoBasicMonitoring(iface, demoDuration); err != nil {
			log.Fatalf("❌ Basic monitoring demo failed: %v", err)
		}

	case "security":
		if err := manager.DemoSecurityFiltering(iface, demoDuration); err != nil {
			log.Fatalf("❌ Security filtering demo failed: %v", err)
		}

		// Add some test IPs to blacklist for demonstration
		log.Println("🔧 Adding test IPs to blacklist for demonstration...")
		testIPs := []string{"192.168.1.100", "10.0.0.50"}
		for _, ip := range testIPs {
			if err := manager.AddIPToBlacklist(ip); err != nil {
				log.Printf("⚠️  Failed to add %s to blacklist: %v", ip, err)
			}
		}

	case "loadbalancer", "lb":
		if err := manager.DemoLoadBalancing(iface, demoDuration); err != nil {
			log.Fatalf("❌ Load balancing demo failed: %v", err)
		}
	}

	log.Println("🎉 Demonstration completed!")
}

func statisticsReporter(ctx context.Context, manager *ebpf.Manager) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printCurrentStats(manager)
		}
	}
}

func printCurrentStats(manager *ebpf.Manager) {
	log.Println("📊 === Current Statistics ===")

	// Global stats
	if stats, err := manager.GetGlobalStats(); err == nil {
		log.Printf("📈 Global: %s", stats.String())
	}

	// Ring Buffer stats
	if rbStats := manager.GetRingBufferStats(); rbStats != nil && rbStats["events_read"] > 0 {
		log.Printf("🔄 Ring Buffer: Read=%d, Dropped=%d, Batches=%d",
			rbStats["events_read"], rbStats["events_dropped"], rbStats["batches_processed"])
	}

	// Mode-specific stats
	mode := manager.GetCurrentXDPMode()
	switch mode {
	case ebpf.XDPAdvancedFilter:
		if secStats, err := manager.GetSecurityStats(); err == nil {
			log.Printf("🛡️  Security: DDoS=%d, Events=%d, Dropped=%d, Blacklisted=%d",
				secStats.DDosBlocked, secStats.SecurityEvents, secStats.XDPDropped, secStats.BlacklistedIPs)
		}

		if blacklisted, err := manager.GetBlacklistedIPs(); err == nil && len(blacklisted) > 0 {
			log.Printf("🚫 Blacklist: %v", blacklisted)
		}

	case ebpf.XDPLoadBalancer:
		if lbStats, err := manager.GetLoadBalancerStats(); err == nil {
			log.Printf("⚖️  Load Balancer: %d decisions", lbStats.LBDecisions)
			for target, count := range lbStats.TargetCounts {
				if lbStats.LBDecisions > 0 {
					percentage := float64(count) / float64(lbStats.LBDecisions) * 100
					log.Printf("   Target %d: %d (%.1f%%)", target, count, percentage)
				}
			}
		}
	}

	// Flow stats summary
	if flowStats, err := manager.GetFlowStats(); err == nil && len(flowStats) > 0 {
		log.Printf("🌊 Active flows: %d", len(flowStats))
	}
}

func printFinalStats(manager *ebpf.Manager) {
	log.Println("📊 === Final Statistics Report ===")

	// Detailed global stats
	if stats, err := manager.GetGlobalStats(); err == nil {
		log.Printf("📈 Total Traffic:")
		log.Printf("   RX: %d packets, %s", stats.RxPackets, formatBytes(stats.RxBytes))
		log.Printf("   TX: %d packets, %s", stats.TxPackets, formatBytes(stats.TxBytes))
	}

	// Ring Buffer performance
	if rbStats := manager.GetRingBufferStats(); rbStats != nil {
		eventsRead := rbStats["events_read"]
		eventsDropped := rbStats["events_dropped"]
		batchesProcessed := rbStats["batches_processed"]

		if eventsRead > 0 {
			dropRate := float64(eventsDropped) / float64(eventsRead) * 100
			log.Printf("🔄 Ring Buffer Performance:")
			log.Printf("   Events: %d read, %d dropped (%.2f%% drop rate)", eventsRead, eventsDropped, dropRate)
			log.Printf("   Batches: %d processed", batchesProcessed)
		}
	}

	// Security summary
	mode := manager.GetCurrentXDPMode()
	if mode == ebpf.XDPAdvancedFilter {
		if secStats, err := manager.GetSecurityStats(); err == nil {
			log.Printf("🛡️  Security Summary:")
			log.Printf("   DDoS attacks blocked: %d", secStats.DDosBlocked)
			log.Printf("   Security events: %d", secStats.SecurityEvents)
			log.Printf("   Packets dropped by XDP: %d", secStats.XDPDropped)
			log.Printf("   Current blacklisted IPs: %d", secStats.BlacklistedIPs)
		}
	}

	// Load balancing summary
	if mode == ebpf.XDPLoadBalancer {
		if lbStats, err := manager.GetLoadBalancerStats(); err == nil {
			log.Printf("⚖️  Load Balancing Summary:")
			log.Printf("   Total decisions: %d", lbStats.LBDecisions)
			log.Printf("   Load distribution:")
			for target, count := range lbStats.TargetCounts {
				if lbStats.LBDecisions > 0 {
					percentage := float64(count) / float64(lbStats.LBDecisions) * 100
					log.Printf("     Target %d: %d packets (%.1f%%)", target, count, percentage)
				}
			}
		}
	}

	// Top flows
	if flowStats, err := manager.GetFlowStats(); err == nil {
		log.Printf("🌊 Flow Statistics: %d total flows", len(flowStats))

		// Find top 5 flows
		type flowInfo struct {
			key   ebpf.FlowKey
			count uint64
		}
		var flows []flowInfo
		for key, count := range flowStats {
			flows = append(flows, flowInfo{key, count})
		}

		// Simple sorting for top flows
		for i := 0; i < len(flows) && i < 5; i++ {
			for j := i + 1; j < len(flows); j++ {
				if flows[j].count > flows[i].count {
					flows[i], flows[j] = flows[j], flows[i]
				}
			}
			if i < len(flows) {
				srcIP := uint32ToIPString(flows[i].key.SrcIP)
				dstIP := uint32ToIPString(flows[i].key.DstIP)
				log.Printf("   Top flow %d: %s:%d -> %s:%d (%d packets)",
					i+1, srcIP, flows[i].key.SrcPort, dstIP, flows[i].key.DstPort, flows[i].count)
			}
		}
	}
}

// Helper function
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

func uint32ToIPString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, ip>>24)
}
