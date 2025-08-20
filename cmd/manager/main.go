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
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"github.com/your-org/kube-net-probe/pkg/controller"
	"github.com/your-org/kube-net-probe/pkg/api"
	"github.com/your-org/kube-net-probe/pkg/collector"
	"github.com/your-org/kube-net-probe/pkg/analyzer"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "kube-net-probe-manager",
		Short: "KubeNetProbe Manager - Kubernetes network monitoring controller",
		Long: `KubeNetProbe Manager is the central controller for the KubeNetProbe system.
It manages eBPF programs deployment, collects network data from agents,
and provides APIs for network monitoring and analysis.`,
		Version: fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date),
		RunE:    runManager,
	}

	var (
		metricsAddr          = rootCmd.Flags().String("metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
		probeAddr            = rootCmd.Flags().String("health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
		enableLeaderElection = rootCmd.Flags().Bool("leader-elect", false, "Enable leader election for controller manager.")
		apiServerAddr        = rootCmd.Flags().String("api-server-addr", ":9090", "The address the API server binds to.")
		configFile           = rootCmd.Flags().String("config", "", "Path to configuration file.")
	)

	// 添加 klog 标志
	klog.InitFlags(flag.CommandLine)
	rootCmd.Flags().AddGoFlagSet(flag.CommandLine)

	if err := rootCmd.Execute(); err != nil {
		klog.ErrorS(err, "Failed to execute command")
		os.Exit(1)
	}

	func runManager(cmd *cobra.Command, args []string) error {
		klog.InfoS("Starting KubeNetProbe Manager", "version", version, "commit", commit, "date", date)

		// 创建 controller runtime manager
		mgr, err := manager.New(manager.Options{
			MetricsBindAddress:      *metricsAddr,
			HealthProbeBindAddress:  *probeAddr,
			LeaderElection:         *enableLeaderElection,
			LeaderElectionID:       "kube-net-probe-manager",
		})
		if err != nil {
			return fmt.Errorf("unable to create manager: %w", err)
		}

		// 初始化控制器
		if err := controller.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup controllers: %w", err)
		}

		// 启动数据收集器
		dataCollector := collector.NewManager()
		if err := mgr.Add(dataCollector); err != nil {
			return fmt.Errorf("unable to add data collector: %w", err)
		}

		// 启动数据分析器
		dataAnalyzer := analyzer.NewManager()
		if err := mgr.Add(dataAnalyzer); err != nil {
			return fmt.Errorf("unable to add data analyzer: %w", err)
		}

		// 启动 API 服务器
		apiServer := api.NewServer(*apiServerAddr)
		if err := mgr.Add(apiServer); err != nil {
			return fmt.Errorf("unable to add API server: %w", err)
		}

		// 设置信号处理
		ctx := signals.SetupSignalHandler()

		klog.InfoS("Starting manager")
		if err := mgr.Start(ctx); err != nil {
			return fmt.Errorf("problem running manager: %w", err)
		}

		return nil
	}
}
