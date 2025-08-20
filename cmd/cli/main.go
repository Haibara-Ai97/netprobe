package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/your-org/kube-net-probe/pkg/cli/commands"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "knp",
		Short: "KubeNetProbe CLI - Command line interface for KubeNetProbe",
		Long: `KubeNetProbe CLI provides a command line interface to interact with
the KubeNetProbe system. You can query network data, manage monitoring
policies, and view system status.`,
		Version: fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date),
	}

	// 全局标志
	var (
		kubeconfig = rootCmd.PersistentFlags().String("kubeconfig", "", "Path to kubeconfig file")
		namespace  = rootCmd.PersistentFlags().StringP("namespace", "n", "default", "Kubernetes namespace")
		output     = rootCmd.PersistentFlags().StringP("output", "o", "table", "Output format (table, json, yaml)")
		verbose    = rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	)

	// 子命令
	rootCmd.AddCommand(
		commands.NewGetCommand(),
		commands.NewDescribeCommand(),
		commands.NewTopCommand(),
		commands.NewPolicyCommand(),
		commands.NewInstallCommand(),
		commands.NewUninstallCommand(),
		commands.NewStatusCommand(),
		commands.NewLogsCommand(),
		commands.NewVersionCommand(version, commit, date),
	)

	// 设置 klog
	if *verbose {
		klog.InitFlags(nil)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
