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
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "netprobe-agent",
		Short: "NetProbe Agent - Network monitoring agent with eBPF",
		Long: `NetProbe Agent runs on each node to collect network traffic data
using eBPF TC programs. It monitors network interfaces and exposes
metrics in Prometheus format for monitoring systems.`,
		Version: fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date),
		RunE:    runAgent,
	}

	var (
		// 这些变量仅用于命令行参数定义，实际值在 runAgent 函数中获取
		_ = rootCmd.Flags().String("node-name", "", "Node name (auto-detected if not specified)")
		_ = rootCmd.Flags().Int("metrics-port", 8081, "Port for Prometheus metrics endpoint")
		_ = rootCmd.Flags().String("metrics-path", "/metrics", "Path for metrics endpoint")
		_ = rootCmd.Flags().Duration("collect-interval", 5*time.Second, "Data collection interval")
		_ = rootCmd.Flags().StringSlice("interface-filter", nil, "Network interfaces to monitor (empty for all)")
		_ = rootCmd.Flags().Bool("active-only", false, "Only export metrics for active interfaces")
		_ = rootCmd.Flags().Bool("debug", false, "Enable debug logging")
		_ = rootCmd.Flags().String("attach-interface", "", "Network interface to attach eBPF programs to")
	)

	// 添加 klog 标志
	klog.InitFlags(flag.CommandLine)
	rootCmd.Flags().AddGoFlagSet(flag.CommandLine)

	if err := rootCmd.Execute(); err != nil {
		klog.ErrorS(err, "Failed to execute command")
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) error {
	klog.InfoS("Starting NetProbe Agent", "version", version, "commit", commit, "date", date)

	// 获取命令行参数值
	nodeName, _ := cmd.Flags().GetString("node-name")
	metricsPort, _ := cmd.Flags().GetInt("metrics-port")
	metricsPath, _ := cmd.Flags().GetString("metrics-path")
	collectInterval, _ := cmd.Flags().GetDuration("collect-interval")
	interfaceFilter, _ := cmd.Flags().GetStringSlice("interface-filter")
	activeOnly, _ := cmd.Flags().GetBool("active-only")
	enableDebug, _ := cmd.Flags().GetBool("debug")
	attachInterface, _ := cmd.Flags().GetString("attach-interface")

	// 避免未使用变量警告
	_ = nodeName

	// 设置日志级别
	if enableDebug {
		// 设置 klog 为详细模式
		flag.Set("v", "2")
		klog.InfoS("Debug logging enabled")
	}

	// 检查 eBPF 支持
	if !ebpf.IsSupported() {
		return fmt.Errorf("eBPF is not supported on this system")
	}
	klog.InfoS("eBPF support verified")

	// 创建 eBPF 管理器
	ebpfManager := ebpf.NewManager()
	
	// 加载网络监控程序
	klog.InfoS("Loading eBPF network monitor programs...")
	if err := ebpfManager.LoadNetworkMonitor(); err != nil {
		return fmt.Errorf("failed to load network monitor: %w", err)
	}
	defer ebpfManager.Close()
	klog.InfoS("eBPF programs loaded successfully")

	// 如果指定了接口，尝试附加程序
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
