package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// NewGetCommand 创建 get 命令
func NewGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get resources from KubeNetProbe",
		Long:  "Get various resources and information from the KubeNetProbe system",
	}

	cmd.AddCommand(
		newGetNetworkCommand(),
		newGetSecurityCommand(),
		newGetPerformanceCommand(),
	)

	return cmd
}

func newGetNetworkCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Get network information",
		RunE:  runGetNetwork,
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "flows",
			Short: "Get network flows",
			RunE:  runGetNetworkFlows,
		},
		&cobra.Command{
			Use:   "connections",
			Short: "Get network connections",
			RunE:  runGetNetworkConnections,
		},
		&cobra.Command{
			Use:   "topology",
			Short: "Get network topology",
			RunE:  runGetNetworkTopology,
		},
	)

	return cmd
}

func newGetSecurityCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Get security information",
		RunE:  runGetSecurity,
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "events",
			Short: "Get security events",
			RunE:  runGetSecurityEvents,
		},
		&cobra.Command{
			Use:   "alerts",
			Short: "Get security alerts",
			RunE:  runGetSecurityAlerts,
		},
	)

	return cmd
}

func newGetPerformanceCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "performance",
		Short: "Get performance information",
		RunE:  runGetPerformance,
	}
}

func runGetNetwork(cmd *cobra.Command, args []string) error {
	fmt.Println("Network Overview:")
	fmt.Println("=================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "METRIC\tVALUE\tUNIT")
	fmt.Fprintln(w, "Packets RX\t12,345\tpackets/s")
	fmt.Fprintln(w, "Packets TX\t67,890\tpackets/s")
	fmt.Fprintln(w, "Bytes RX\t1.2\tGB/s")
	fmt.Fprintln(w, "Bytes TX\t2.4\tGB/s")
	fmt.Fprintln(w, "Active Connections\t150\tconnections")
	w.Flush()

	return nil
}

func runGetNetworkFlows(cmd *cobra.Command, args []string) error {
	fmt.Println("Active Network Flows:")
	fmt.Println("====================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tDESTINATION\tPROTOCOL\tPORT\tPACKETS\tBYTES")
	fmt.Fprintln(w, "10.244.1.10\t10.244.2.20\tTCP\t80\t1,234\t128KB")
	fmt.Fprintln(w, "10.244.1.11\t10.244.2.21\tHTTP\t8080\t5,678\t512KB")
	fmt.Fprintln(w, "10.244.1.12\t10.244.2.22\tgRPC\t9090\t9,012\t1.2MB")
	w.Flush()

	return nil
}

func runGetNetworkConnections(cmd *cobra.Command, args []string) error {
	fmt.Println("Network Connections:")
	fmt.Println("===================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE POD\tTARGET POD\tPROTOCOL\tPORT\tSTATE\tDURATION")
	fmt.Fprintln(w, "app-pod-1\tdb-pod-1\tTCP\t5432\tESTABLISHED\t5m30s")
	fmt.Fprintln(w, "web-pod-1\tapp-pod-1\tHTTP\t8080\tESTABLISHED\t2m15s")
	fmt.Fprintln(w, "app-pod-2\tcache-pod-1\tTCP\t6379\tESTABLISHED\t1m45s")
	w.Flush()

	return nil
}

func runGetNetworkTopology(cmd *cobra.Command, args []string) error {
	fmt.Println("Network Topology:")
	fmt.Println("================")
	fmt.Println()
	fmt.Println("┌─────────────┐    ┌─────────────┐    ┌─────────────┐")
	fmt.Println("│   web-pod   │───▶│   app-pod   │───▶│   db-pod    │")
	fmt.Println("│  (frontend) │    │ (backend)   │    │ (database)  │")
	fmt.Println("└─────────────┘    └─────────────┘    └─────────────┘")
	fmt.Println("      │                   │                   │")
	fmt.Println("      ▼                   ▼                   ▼")
	fmt.Println("┌─────────────┐    ┌─────────────┐    ┌─────────────┐")
	fmt.Println("│ nginx-svc   │    │  app-svc    │    │ postgres-svc│")
	fmt.Println("│   :80       │    │  :8080      │    │   :5432     │")
	fmt.Println("└─────────────┘    └─────────────┘    └─────────────┘")

	return nil
}

func runGetSecurity(cmd *cobra.Command, args []string) error {
	fmt.Println("Security Overview:")
	fmt.Println("=================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "METRIC\tVALUE\tSTATUS")
	fmt.Fprintln(w, "Security Events\t5\tLOW")
	fmt.Fprintln(w, "Active Alerts\t1\tMEDIUM")
	fmt.Fprintln(w, "Policy Violations\t0\tOK")
	fmt.Fprintln(w, "Suspicious Connections\t2\tLOW")
	w.Flush()

	return nil
}

func runGetSecurityEvents(cmd *cobra.Command, args []string) error {
	fmt.Println("Recent Security Events:")
	fmt.Println("======================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tTYPE\tSOURCE\tTARGET\tSEVERITY\tDESCRIPTION")
	fmt.Fprintln(w, "2m ago\tPort Scan\t192.168.1.100\t10.244.1.10\tMedium\tPort scan detected")
	fmt.Fprintln(w, "5m ago\tSuspicious Connection\t10.244.1.15\t10.244.2.25\tLow\tUnusual traffic pattern")
	fmt.Fprintln(w, "10m ago\tPolicy Violation\t10.244.1.20\t0.0.0.0/0\tHigh\tOutbound connection blocked")
	w.Flush()

	return nil
}

func runGetSecurityAlerts(cmd *cobra.Command, args []string) error {
	fmt.Println("Active Security Alerts:")
	fmt.Println("======================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEVERITY\tTITLE\tSTATUS\tCREATED")
	fmt.Fprintln(w, "ALT-001\tMedium\tSuspicious network activity\tActive\t2m ago")
	fmt.Fprintln(w, "ALT-002\tLow\tUnusual connection pattern\tInvestigating\t15m ago")
	w.Flush()

	return nil
}

func runGetPerformance(cmd *cobra.Command, args []string) error {
	fmt.Println("Performance Overview:")
	fmt.Println("====================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "METRIC\tVALUE\tTHRESHOLD\tSTATUS")
	fmt.Fprintln(w, "Average Latency\t10ms\t<50ms\tOK")
	fmt.Fprintln(w, "P99 Latency\t45ms\t<100ms\tOK")
	fmt.Fprintln(w, "Throughput\t1000 req/s\t>500 req/s\tOK")
	fmt.Fprintln(w, "Error Rate\t0.1%\t<1%\tOK")
	fmt.Fprintln(w, "Packet Loss\t0.01%\t<0.1%\tOK")
	w.Flush()

	return nil
}
