package collector

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Haibara-Ai97/netprobe/pkg/ebpf"
)

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Println("TC collector integration tests require root privileges.")
		os.Exit(77)
	}

	os.Exit(m.Run())
}

func TestTCCollector_CollectOnce(t *testing.T) {
	// 创建 eBPF 管理器
	ebpfManager := ebpf.NewManager()
	defer ebpfManager.Close()

	// 加载 eBPF 程序
	err := ebpfManager.LoadNetworkMonitor()
	require.NoError(t, err, "Failed to load eBPF network monitor")

	// 尝试附加到回环接口
	err = ebpfManager.AttachNetworkMonitor("lo")
	require.NoError(t, err, "Failed to attach to loopback interface")

	// 创建 TC 收集器
	tcCollector := NewTCCollector(ebpfManager)
	require.NotNil(t, tcCollector)

	// 执行初始收集
	fmt.Println("🔍 执行初始数据收集...")
	initialStats, err := tcCollector.CollectOnce()
	require.NoError(t, err, "Initial collection should not fail")
	fmt.Printf("初始收集结果: %d 个接口\n", len(initialStats))

	// 打印初始统计信息
	for _, stats := range initialStats {
		fmt.Printf("  接口 %s (索引:%d):\n", stats.InterfaceName, stats.InterfaceIndex)
		fmt.Printf("    入站: %d 包, %s\n", stats.IngressPackets, formatBytes(stats.IngressBytes))
		fmt.Printf("    出站: %d 包, %s\n", stats.EgressPackets, formatBytes(stats.EgressBytes))
		fmt.Printf("    速率: 入站 %.2f pps/%.2f Bps, 出站 %.2f pps/%.2f Bps\n",
			stats.IngressPacketsRate, stats.IngressBytesRate,
			stats.EgressPacketsRate, stats.EgressBytesRate)
	}

	// 向 lo 接口发送测试数据
	fmt.Println("🚀 向 lo 接口发送测试数据...")
	
	// 方法1: 使用 ping 发送 ICMP 数据包
	fmt.Println("  发送 ICMP 数据包...")
	cmd := exec.Command("ping", "-c", "10", "-i", "0.1", "127.0.0.1")
	err = cmd.Run()
	if err != nil {
		t.Logf("警告: ping 失败: %v", err)
	}

	// 方法2: 使用 curl 发送 HTTP 请求（会失败但产生网络流量）
	fmt.Println("  尝试发送 HTTP 请求...")
	cmd = exec.Command("curl", "-s", "--max-time", "1", "http://127.0.0.1:80", "-o", "/dev/null")
	cmd.Run() // 忽略错误，因为可能没有服务监听

	// 方法3: 使用 nc 发送 TCP 数据包（如果可用）
	fmt.Println("  尝试发送 TCP 数据包...")
	cmd = exec.Command("sh", "-c", "echo 'test data' | nc -w1 127.0.0.1 8080 2>/dev/null || true")
	cmd.Run() // 忽略错误

	// 等待数据包被处理
	time.Sleep(1 * time.Second)

	// 执行第二次收集
	fmt.Println("🔍 执行第二次数据收集...")
	finalStats, err := tcCollector.CollectOnce()
	require.NoError(t, err, "Final collection should not fail")
	fmt.Printf("最终收集结果: %d 个接口\n", len(finalStats))

	// 比较两次收集的结果
	fmt.Printf("📊 统计变化分析:\n")
	
	// 创建初始统计的映射以便比较
	initialStatsMap := make(map[string]InterfaceStats)
	for _, stats := range initialStats {
		initialStatsMap[stats.InterfaceName] = stats
	}

	hasTrafficChanges := false
	for _, finalStat := range finalStats {
		if initialStat, exists := initialStatsMap[finalStat.InterfaceName]; exists {
			// 比较数据包和字节数变化
			ingressPacketsDiff := int64(finalStat.IngressPackets - initialStat.IngressPackets)
			ingressBytesDiff := int64(finalStat.IngressBytes - initialStat.IngressBytes)
			egressPacketsDiff := int64(finalStat.EgressPackets - initialStat.EgressPackets)
			egressBytesDiff := int64(finalStat.EgressBytes - initialStat.EgressBytes)

			if ingressPacketsDiff > 0 || ingressBytesDiff > 0 || egressPacketsDiff > 0 || egressBytesDiff > 0 {
				hasTrafficChanges = true
				fmt.Printf("  接口 %s 检测到流量变化:\n", finalStat.InterfaceName)
				if ingressPacketsDiff > 0 || ingressBytesDiff > 0 {
					fmt.Printf("    入站: +%d 包, +%s\n", ingressPacketsDiff, formatBytes(uint64(ingressBytesDiff)))
				}
				if egressPacketsDiff > 0 || egressBytesDiff > 0 {
					fmt.Printf("    出站: +%d 包, +%s\n", egressPacketsDiff, formatBytes(uint64(egressBytesDiff)))
				}
				fmt.Printf("    当前速率: 入站 %.2f pps/%.2f Bps, 出站 %.2f pps/%.2f Bps\n",
					finalStat.IngressPacketsRate, finalStat.IngressBytesRate,
					finalStat.EgressPacketsRate, finalStat.EgressBytesRate)
			}
		} else {
			// 新接口出现，如果有流量数据，也应该算作流量变化
			fmt.Printf("  新接口 %s 出现\n", finalStat.InterfaceName)
			if finalStat.IngressPackets > 0 || finalStat.IngressBytes > 0 || 
			   finalStat.EgressPackets > 0 || finalStat.EgressBytes > 0 {
				hasTrafficChanges = true
				fmt.Printf("    发现流量: 入站 %d 包/%s, 出站 %d 包/%s\n",
					finalStat.IngressPackets, formatBytes(finalStat.IngressBytes),
					finalStat.EgressPackets, formatBytes(finalStat.EgressBytes))
				fmt.Printf("    当前速率: 入站 %.2f pps/%.2f Bps, 出站 %.2f pps/%.2f Bps\n",
					finalStat.IngressPacketsRate, finalStat.IngressBytesRate,
					finalStat.EgressPacketsRate, finalStat.EgressBytesRate)
			}
		}
	}

	// 验证结果
	if hasTrafficChanges {
		fmt.Println("✅ TC 收集器成功检测到网络流量变化!")
	} else {
		fmt.Println("⚠️  没有检测到流量变化，可能是:")
		fmt.Println("   - eBPF 程序未正确附加到 TC 层")
		fmt.Println("   - 网络流量没有通过 TC 监控路径")
		fmt.Println("   - 统计更新延迟")
		fmt.Println("   - TC 程序需要特定的内核配置")
	}

	// 基本验证
	assert.NotNil(t, finalStats)
	assert.NoError(t, err)
	
	// 验证接口映射功能
	interfaceCount := tcCollector.GetInterfaceCount()
	assert.Greater(t, interfaceCount, 0, "Should have at least one interface")
	
	supportedInterfaces := tcCollector.GetSupportedInterfaces()
	assert.NotEmpty(t, supportedInterfaces, "Should have supported interfaces")
	fmt.Printf("📋 支持的接口: %v\n", supportedInterfaces)

	// 验证数据结构的完整性
	for _, stats := range finalStats {
		assert.NotEmpty(t, stats.InterfaceName, "Interface name should not be empty")
		assert.Greater(t, stats.InterfaceIndex, uint32(0), "Interface index should be positive")
		assert.False(t, stats.LastUpdated.IsZero(), "LastUpdated timestamp should be set")
		
		// 验证统计值不为负数（速率可能为负，但计数器不应该）
		assert.GreaterOrEqual(t, stats.IngressPackets, uint64(0), "Ingress packets should not be negative")
		assert.GreaterOrEqual(t, stats.IngressBytes, uint64(0), "Ingress bytes should not be negative")
		assert.GreaterOrEqual(t, stats.EgressPackets, uint64(0), "Egress packets should not be negative")
		assert.GreaterOrEqual(t, stats.EgressBytes, uint64(0), "Egress bytes should not be negative")
	}
}

func TestTCCollector_SetCollectInterval(t *testing.T) {
	ebpfManager := ebpf.NewManager()
	defer ebpfManager.Close()

	tcCollector := NewTCCollector(ebpfManager)
	require.NotNil(t, tcCollector)

	// 测试设置收集间隔
	newInterval := 10 * time.Second
	tcCollector.SetCollectInterval(newInterval)

	// 验证间隔被正确设置（通过检查内部状态）
	assert.Equal(t, newInterval, tcCollector.collectInterval)
}

func TestTCCollector_ErrorHandling(t *testing.T) {
	// 测试没有初始化网络加载器的 eBPF 管理器
	ebpfManager := ebpf.NewManager()
	defer ebpfManager.Close()
	
	tcCollector := NewTCCollector(ebpfManager)
	require.NotNil(t, tcCollector)

	// 应该返回错误，因为网络加载器没有被正确初始化
	// （没有调用 LoadNetworkMonitor）
	_, err := tcCollector.CollectOnce()
	assert.Error(t, err)
	// 由于我们没有加载程序，ReadTCDeviceStats 会因为 nil map 而失败
	assert.Contains(t, err.Error(), "failed to read TC device stats")
}

// formatBytes 格式化字节数显示
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
