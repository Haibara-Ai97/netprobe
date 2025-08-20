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

	"github.com/your-org/kube-net-probe/pkg/agent"
	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "kube-net-probe-agent",
		Short: "KubeNetProbe Agent - Node-level network monitoring agent",
		Long: `KubeNetProbe Agent runs on each Kubernetes node to collect network data
using eBPF programs. It monitors network traffic, security events, and
performance metrics, then sends the data to the central manager.`,
		Version: fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date),
		RunE:    runAgent,
	}

	var (
		nodeName     = rootCmd.Flags().String("node-name", "", "Kubernetes node name (auto-detected if not specified)")
		managerAddr  = rootCmd.Flags().String("manager-address", "kube-net-probe-manager:9090", "Address of the KubeNetProbe manager")
		metricsAddr  = rootCmd.Flags().String("metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
		configFile   = rootCmd.Flags().String("config", "", "Path to configuration file.")
		ebpfPrograms = rootCmd.Flags().StringSlice("ebpf-programs", []string{"network", "security", "performance"}, "List of eBPF programs to load")
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
	klog.InfoS("Starting KubeNetProbe Agent", "version", version, "commit", commit, "date", date)

	// 检查 eBPF 支持
	if !ebpf.IsSupported() {
		return fmt.Errorf("eBPF is not supported on this system")
	}

	// 创建 agent 实例
	agentConfig := &agent.Config{
		NodeName:     *nodeName,
		ManagerAddr:  *managerAddr,
		MetricsAddr:  *metricsAddr,
		EBPFPrograms: *ebpfPrograms,
	}

	agent, err := agent.New(agentConfig)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 启动 agent
	errCh := make(chan error, 1)
	go func() {
		if err := agent.Run(ctx); err != nil {
			errCh <- fmt.Errorf("agent run failed: %w", err)
		}
	}()

	// 等待信号或错误
	select {
	case sig := <-sigCh:
		klog.InfoS("Received signal, shutting down", "signal", sig)
		cancel()

		// 给 agent 一些时间来清理
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := agent.Shutdown(shutdownCtx); err != nil {
			klog.ErrorS(err, "Failed to shutdown agent gracefully")
		}

	case err := <-errCh:
		return err
	}

	return nil
}
