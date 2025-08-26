package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
	"github.com/your-org/kube-net-probe/pkg/metrics"
)

var (
	version = "dev"     // Application version (set during build)
	commit  = "unknown" // Git commit hash (set during build)
	date    = "unknown" // Build date (set during build)
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "netprobe-agent",
		Short: "NetProbe Agent - High-performance network monitoring with eBPF",
		Long: `NetProbe Agent is a network monitoring tool that uses eBPF TC programs
to collect network traffic statistics. It monitors network interfaces at the
Traffic Control layer and exposes metrics in Prometheus format.

Features:
- Zero-copy packet processing with eBPF
- Per-interface traffic statistics (ingress/egress)  
- Real-time rate calculations (packets/sec, bytes/sec)
- Prometheus-compatible metrics export
- Low overhead monitoring suitable for production`,
		Version: fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date),
		RunE:    runAgent,
	}

	// Command-line flags for agent configuration
	// Note: We only define flags here, values are retrieved in runAgent()
	var (
		_ = rootCmd.Flags().String("node-name", "", "Node name for identification (auto-detected if not specified)")
		_ = rootCmd.Flags().Int("metrics-port", 8081, "HTTP port for Prometheus metrics endpoint")
		_ = rootCmd.Flags().String("metrics-path", "/metrics", "URL path for metrics endpoint")
		_ = rootCmd.Flags().Duration("collect-interval", 5*time.Second, "Interval between data collection cycles")
		_ = rootCmd.Flags().StringSlice("interface-filter", nil, "Network interfaces to monitor (empty for all interfaces)")
		_ = rootCmd.Flags().Bool("active-only", false, "Only export metrics for interfaces with active traffic")
		_ = rootCmd.Flags().Bool("debug", false, "Enable debug logging output")
		_ = rootCmd.Flags().String("attach-interface", "", "Specific interface to attach eBPF programs to")
	)

	// Add klog flags for advanced logging control
	klog.InitFlags(flag.CommandLine)
	rootCmd.Flags().AddGoFlagSet(flag.CommandLine)

	if err := rootCmd.Execute(); err != nil {
		klog.ErrorS(err, "Failed to execute command")
		os.Exit(1)
	}
}

// runAgent is the main entry point for the NetProbe agent
// Handles initialization, eBPF program loading, and metrics collection
func runAgent(cmd *cobra.Command, args []string) error {
	klog.InfoS("Starting NetProbe Agent", "version", version, "commit", commit, "date", date)

	// Extract command-line flag values
	nodeName, _ := cmd.Flags().GetString("node-name")
	metricsPort, _ := cmd.Flags().GetInt("metrics-port")
	metricsPath, _ := cmd.Flags().GetString("metrics-path")
	collectInterval, _ := cmd.Flags().GetDuration("collect-interval")
	interfaceFilter, _ := cmd.Flags().GetStringSlice("interface-filter")
	activeOnly, _ := cmd.Flags().GetBool("active-only")
	enableDebug, _ := cmd.Flags().GetBool("debug")
	attachInterface, _ := cmd.Flags().GetString("attach-interface")

	// Suppress unused variable warning for nodeName (may be used in future)
	_ = nodeName

	// Configure debug logging if requested
	if enableDebug {
		flag.Set("v", "2") // Set klog to verbose level 2
		klog.InfoS("Debug logging enabled")
	}

	// Verify eBPF support on the current system
	if !ebpf.IsSupported() {
		return fmt.Errorf("eBPF is not supported on this system - requires Linux kernel >= 4.15")
	}
	klog.InfoS("eBPF support verified")

	// Initialize eBPF program manager
	ebpfManager := ebpf.NewManager()
	
	// Load network monitoring eBPF programs into kernel
	klog.InfoS("Loading eBPF network monitor programs...")
	if err := ebpfManager.LoadNetworkMonitor(); err != nil {
		return fmt.Errorf("failed to load network monitor: %w", err)
	}
	defer ebpfManager.Close() // Ensure cleanup on exit
	klog.InfoS("eBPF programs loaded successfully")

	// Attach eBPF programs to specific interface if requested
	if attachInterface != "" {
		klog.InfoS("Attaching eBPF programs to interface", "interface", attachInterface)
		if err := ebpfManager.AttachNetworkMonitor(attachInterface); err != nil {
			klog.ErrorS(err, "Failed to attach eBPF programs", "interface", attachInterface)
			klog.InfoS("Note: You may need to manually attach TC programs using tc commands")
		} else {
			klog.InfoS("eBPF programs attached successfully", "interface", attachInterface)
		}
	}

	// 创建 metrics 导出器配置
	exporterConfig := &metrics.ExporterConfig{
		ServerConfig: &metrics.ServerConfig{
			Port:         metricsPort,
			Path:         metricsPath,
			EnableCORS:   true,
			EnableGzip:   true,
		},
		CollectInterval:  collectInterval,
		InterfaceFilter:  interfaceFilter,
		EnableActiveOnly: activeOnly,
		LogLevel:        getLogLevel(enableDebug),
	}

	// 创建 metrics 导出器
	exporter := metrics.NewExporter(ebpfManager, exporterConfig)

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 启动 metrics 导出器
	klog.InfoS("Starting metrics exporter", "port", metricsPort, "path", metricsPath)
	if err := exporter.Start(ctx); err != nil {
		return fmt.Errorf("failed to start metrics exporter: %w", err)
	}
	defer exporter.Stop()

	// 等待导出器准备就绪
	klog.InfoS("Waiting for exporter to be ready...")
	if err := exporter.WaitForReady(30 * time.Second); err != nil {
		return fmt.Errorf("exporter not ready: %w", err)
	}

	// 打印启动信息
	klog.InfoS("NetProbe Agent started successfully")
	klog.InfoS("Metrics endpoint", "url", exporter.GetMetricsURL())
	klog.InfoS("Health endpoint", "url", exporter.GetHealthURL())
	
	if len(interfaceFilter) > 0 {
		klog.InfoS("Monitoring specific interfaces", "interfaces", interfaceFilter)
	} else {
		klog.InfoS("Monitoring all network interfaces")
	}
	
	if activeOnly {
		klog.InfoS("Only active interfaces will be exported")
	}

	// 定期打印状态信息
	statusTicker := time.NewTicker(30 * time.Second)
	defer statusTicker.Stop()

	// 等待信号或错误
	for {
		select {
		case sig := <-sigCh:
			klog.InfoS("Received signal, shutting down", "signal", sig)
			cancel()

			// 给导出器一些时间来清理
			if err := exporter.Stop(); err != nil {
				klog.ErrorS(err, "Failed to shutdown exporter gracefully")
			}

			klog.InfoS("NetProbe Agent stopped")
			return nil

		case <-statusTicker.C:
			// 打印状态信息
			if enableDebug {
				status := exporter.GetStatus()
				klog.InfoS("Agent status update",
					"collections", status.TotalCollections,
					"errors", status.TotalErrors,
					"metrics", status.ServerStats.MetricCount,
					"requests", status.ServerStats.RequestCount)
			}

		case <-ctx.Done():
			klog.InfoS("Context cancelled, stopping agent")
			return nil
		}
	}
}

// getLogLevel 根据调试标志返回日志级别
func getLogLevel(debug bool) string {
	if debug {
		return "debug"
	}
	return "info"
}
