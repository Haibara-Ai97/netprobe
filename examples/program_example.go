package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: program_example <interface_name>")
		os.Exit(1)
	}

	interfaceName := os.Args[1]

	// 创建 XDP 程序规范
	xdpSpec := &ebpf.ProgramSpec{
		Name:       "network_monitor_xdp",
		Type:       ebpf.ProgramTypeXDP,
		ObjectFile: "bin/ebpf/network-monitor.o",
		Section:    "xdp",
		AttachTo:   interfaceName,
	}

	// 加载并附加 XDP 程序
	xdpProgram, err := ebpf.NewProgram(xdpSpec)
	if err != nil {
		log.Fatalf("Failed to create XDP program: %v", err)
	}
	defer xdpProgram.Close()

	fmt.Printf("✅ XDP program attached to interface %s\n", interfaceName)

	// 创建 kprobe 程序规范 (示例)
	kprobeSpec := &ebpf.ProgramSpec{
		Name:       "trace_tcp_connect",
		Type:       ebpf.ProgramTypeKprobe,
		ObjectFile: "bin/ebpf/network-monitor.o",
		Section:    "kprobe",
		AttachTo:   "tcp_v4_connect",
	}

	// 尝试加载 kprobe 程序
	kprobeProgram, err := ebpf.NewProgram(kprobeSpec)
	if err != nil {
		fmt.Printf("⚠️  Failed to create kprobe program: %v\n", err)
	} else {
		defer kprobeProgram.Close()
		fmt.Println("✅ Kprobe program attached to tcp_v4_connect")
	}

	// 获取并显示 Maps
	if xdpProgram != nil {
		if statsMap, err := xdpProgram.GetMap("packet_stats"); err == nil {
			fmt.Println("✅ Found packet_stats map")
			_ = statsMap // 在实际使用中会读取数据
		}

		if flowMap, err := xdpProgram.GetMap("flow_stats"); err == nil {
			fmt.Println("✅ Found flow_stats map")
			_ = flowMap // 在实际使用中会读取数据
		}
	}

	fmt.Println("📊 Programs are running. Press Ctrl+C to stop.")

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n🛑 Shutting down...")
}
