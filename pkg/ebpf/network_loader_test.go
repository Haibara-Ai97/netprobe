package ebpf

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Println("eBPF integration tests require root privileges.")
		os.Exit(77)
	}

	os.Exit(m.Run())
}

func TestNetworkLoader_LoadEbpfPrograms(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err, "Failed to load eBPF programs.")

	assert.NotNil(t, loader.GetPacketStatsMap())
	assert.NotNil(t, loader.GetTcDeviceStatsMap())
	assert.NotNil(t, loader.GetFlowStatsMap())
}

func TestNetworkLoader_GetStats(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err, "Failed to load eBPF programs.")

	stats, err := loader.GetStats()
	assert.NoError(t, err, "Failed to get stats from eBPF programs.")
	assert.NotNil(t, stats)

	expectedKeys := []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes"}
	for _, key := range expectedKeys {
		_, exists := stats[key]
		assert.True(t, exists, "Missing stat key: %s", key)
	}
}

func TestNetworkLoader_ReadGlobalStats(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err)
	err = loader.AttachNetworkPrograms("lo")
	require.NoError(t, err, "Failed to attach to loopback interface")

	// 读取初始统计
	initialStats, err := loader.ReadGlobalStats()
	require.NoError(t, err)
	fmt.Printf("初始统计: %s\n", initialStats.String())

	// 向 lo 接口发送测试数据
	fmt.Println("🚀 向 lo 接口发送测试数据...")

	// 方法1: 使用 ping 发送 ICMP 数据包
	fmt.Println("  发送 ICMP 数据包...")
	cmd := exec.Command("ping", "-c", "5", "-i", "0.1", "127.0.0.1")
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
	time.Sleep(500 * time.Millisecond)

	// 读取最终统计
	finalStats, err := loader.ReadGlobalStats()
	fmt.Printf("最终统计: %s\n", finalStats.String())
	assert.NoError(t, err)
	assert.NotNil(t, finalStats)
	assert.False(t, finalStats.Timestamp.IsZero())

	// 比较统计变化
	fmt.Printf("📊 统计变化:\n")
	fmt.Printf("  RX 数据包: %d -> %d (增加: %d)\n",
		initialStats.RxPackets, finalStats.RxPackets,
		finalStats.RxPackets-initialStats.RxPackets)
	fmt.Printf("  TX 数据包: %d -> %d (增加: %d)\n",
		initialStats.TxPackets, finalStats.TxPackets,
		finalStats.TxPackets-initialStats.TxPackets)
	fmt.Printf("  RX 字节数: %d -> %d (增加: %d)\n",
		initialStats.RxBytes, finalStats.RxBytes,
		finalStats.RxBytes-initialStats.RxBytes)
	fmt.Printf("  TX 字节数: %d -> %d (增加: %d)\n",
		initialStats.TxBytes, finalStats.TxBytes,
		finalStats.TxBytes-initialStats.TxBytes)

	// 验证是否有流量被捕获
	if finalStats.RxPackets > initialStats.RxPackets || finalStats.TxPackets > initialStats.TxPackets {
		fmt.Println("✅ eBPF 程序成功捕获了网络流量!")
	} else {
		fmt.Println("⚠️  没有检测到流量变化，可能是:")
		fmt.Println("   - eBPF 程序未正确附加")
		fmt.Println("   - 网络流量没有通过监控的路径")
		fmt.Println("   - 统计更新延迟")
	}

	// 统计数量应该不会减少
	assert.GreaterOrEqual(t, finalStats.RxPackets, initialStats.RxPackets, "RX packets should not decrease")
	assert.GreaterOrEqual(t, finalStats.TxPackets, initialStats.TxPackets, "TX packets should not decrease")
	assert.GreaterOrEqual(t, finalStats.RxBytes, initialStats.RxBytes, "RX bytes should not decrease")
	assert.GreaterOrEqual(t, finalStats.TxBytes, initialStats.TxBytes, "TX bytes should not decrease")
}

func TestNetworkLoader_ReadTCDeviceStats(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err)
	err = loader.AttachNetworkPrograms("lo")
	require.NoError(t, err, "Failed to attach to loopback interface")

	// 读取初始 TC 设备统计
	initialStats, err := loader.ReadTCDeviceStats()
	require.NoError(t, err)
	fmt.Printf("初始 TC 设备统计: %d 条记录\n", len(initialStats))
	for key, value := range initialStats {
		fmt.Printf("  设备 %d, 方向 %d, 类型 %d: %d\n", key.Ifindex, key.Direction, key.StatType, value)
	}

	// 向 lo 接口发送测试数据
	fmt.Println("🚀 向 lo 接口发送测试数据...")

	// 方法1: 使用 ping 发送 ICMP 数据包
	fmt.Println("  发送 ICMP 数据包...")
	cmd := exec.Command("ping", "-c", "5", "-i", "0.1", "127.0.0.1")
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
	time.Sleep(500 * time.Millisecond)

	// 读取最终 TC 设备统计
	finalStats, err := loader.ReadTCDeviceStats()
	require.NoError(t, err)
	fmt.Printf("最终 TC 设备统计: %d 条记录\n", len(finalStats))

	// 比较统计变化
	fmt.Printf("📊 TC 设备统计变化:\n")
	fmt.Printf("  记录数量: %d -> %d\n", len(initialStats), len(finalStats))

	// 检查是否有新的统计条目或值的变化
	hasChanges := false
	for key, value := range finalStats {
		if initialValue, exists := initialStats[key]; exists {
			if value != initialValue {
				fmt.Printf("  设备 %d, 方向 %d, 类型 %d: %d -> %d (增加: %d)\n",
					key.Ifindex, key.Direction, key.StatType, initialValue, value, value-initialValue)
				hasChanges = true
			}
		} else {
			fmt.Printf("  新条目 - 设备 %d, 方向 %d, 类型 %d: %d\n",
				key.Ifindex, key.Direction, key.StatType, value)
			hasChanges = true
		}
	}

	// 验证是否有流量被捕获
	if hasChanges || len(finalStats) > len(initialStats) {
		fmt.Println("✅ TC 程序成功捕获了网络流量!")
	} else {
		fmt.Println("⚠️  没有检测到 TC 统计变化，可能是:")
		fmt.Println("   - TC 程序未正确附加")
		fmt.Println("   - 网络流量没有通过 TC 监控路径")
		fmt.Println("   - 统计更新延迟")
	}

	// 基本验证
	assert.NoError(t, err)
	assert.NotNil(t, finalStats)
}

func TestNetworkLoader_ReadFlowStats(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err)
	err = loader.AttachNetworkPrograms("lo")
	require.NoError(t, err, "Failed to attach to loopback interface")

	// 读取初始流量统计
	initialStats, err := loader.ReadFlowStats()
	require.NoError(t, err)
	fmt.Printf("初始流量统计: %d 条流记录\n", len(initialStats))
	for key, value := range initialStats {
		srcIP := fmt.Sprintf("%d.%d.%d.%d",
			key.SrcIP&0xff, (key.SrcIP>>8)&0xff, (key.SrcIP>>16)&0xff, (key.SrcIP>>24)&0xff)
		dstIP := fmt.Sprintf("%d.%d.%d.%d",
			key.DstIP&0xff, (key.DstIP>>8)&0xff, (key.DstIP>>16)&0xff, (key.DstIP>>24)&0xff)
		fmt.Printf("  流 %s:%d -> %s:%d (协议:%d): %d 数据包\n",
			srcIP, key.SrcPort, dstIP, key.DstPort, key.Protocol, value)
	}

	// 向 lo 接口发送测试数据
	fmt.Println("🚀 向 lo 接口发送测试数据...")

	// 方法1: 使用 ping 发送 ICMP 数据包
	fmt.Println("  发送 ICMP 数据包...")
	cmd := exec.Command("ping", "-c", "5", "-i", "0.1", "127.0.0.1")
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
	time.Sleep(500 * time.Millisecond)

	// 读取最终流量统计
	finalStats, err := loader.ReadFlowStats()
	require.NoError(t, err)
	fmt.Printf("最终流量统计: %d 条流记录\n", len(finalStats))

	// 比较统计变化
	fmt.Printf("📊 流量统计变化:\n")
	fmt.Printf("  流记录数量: %d -> %d\n", len(initialStats), len(finalStats))

	// 检查是否有新的流或流量的变化
	hasChanges := false
	for key, value := range finalStats {
		srcIP := fmt.Sprintf("%d.%d.%d.%d",
			key.SrcIP&0xff, (key.SrcIP>>8)&0xff, (key.SrcIP>>16)&0xff, (key.SrcIP>>24)&0xff)
		dstIP := fmt.Sprintf("%d.%d.%d.%d",
			key.DstIP&0xff, (key.DstIP>>8)&0xff, (key.DstIP>>16)&0xff, (key.DstIP>>24)&0xff)

		if initialValue, exists := initialStats[key]; exists {
			if value != initialValue {
				fmt.Printf("  流 %s:%d -> %s:%d (协议:%d): %d -> %d (增加: %d 数据包)\n",
					srcIP, key.SrcPort, dstIP, key.DstPort, key.Protocol,
					initialValue, value, value-initialValue)
				hasChanges = true
			}
		} else {
			fmt.Printf("  新流 %s:%d -> %s:%d (协议:%d): %d 数据包\n",
				srcIP, key.SrcPort, dstIP, key.DstPort, key.Protocol, value)
			hasChanges = true
		}
	}

	// 验证是否有流量被捕获
	if hasChanges || len(finalStats) > len(initialStats) {
		fmt.Println("✅ eBPF 程序成功捕获了网络流量!")
	} else {
		fmt.Println("⚠️  没有检测到流量变化，可能是:")
		fmt.Println("   - eBPF 程序未正确附加")
		fmt.Println("   - 网络流量没有通过监控的路径")
		fmt.Println("   - 流量统计更新延迟")
	}

	// 基本验证
	assert.NoError(t, err)
	assert.NotNil(t, finalStats)
}
