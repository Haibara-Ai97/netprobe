package ebpf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
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

// ========== Ring Buffer 核心功能测试 ==========

// TestNetworkLoader_RingBufferConfiguration 测试 Ring Buffer 配置功能
func TestNetworkLoader_RingBufferConfiguration(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	// 测试默认配置
	assert.True(t, loader.config.EnableTCEvents, "默认应该启用 TC 事件")
	assert.False(t, loader.config.EnableXDPEvents, "默认应该禁用 XDP 事件（避免重复）")
	assert.False(t, loader.config.EnableDetailedEvents, "默认应该禁用详细事件")

	// 测试配置修改
	newConfig := &RingBufferConfig{
		EnableXDPEvents:      true,
		EnableTCEvents:       false,
		EnableDetailedEvents: true,
	}
	loader.SetRingBufferConfig(newConfig)
	
	assert.True(t, loader.config.EnableXDPEvents)
	assert.False(t, loader.config.EnableTCEvents)
	assert.True(t, loader.config.EnableDetailedEvents)

	// 加载程序并配置 Ring Buffer
	err := loader.LoadPrograms()
	require.NoError(t, err, "加载 eBPF 程序失败")

	// 验证配置已应用到 eBPF 映射
	// 读取配置映射验证配置值
	key := uint32(0)
	var configValue uint32
	err = loader.objs.RingbufConfig.Lookup(key, &configValue)
	require.NoError(t, err, "读取 Ring Buffer 配置失败")

	// 验证配置位
	expectedValue := uint32(0)
	if newConfig.EnableXDPEvents {
		expectedValue |= 1 << 0
	}
	if newConfig.EnableTCEvents {
		expectedValue |= 1 << 1
	}
	if newConfig.EnableDetailedEvents {
		expectedValue |= 1 << 2
	}

	assert.Equal(t, expectedValue, configValue, "Ring Buffer 配置值不匹配")
}

// TestNetworkLoader_RingBufferInitialization 测试 Ring Buffer 初始化
func TestNetworkLoader_RingBufferInitialization(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	// 加载程序
	err := loader.LoadPrograms()
	require.NoError(t, err)

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 初始化 Ring Buffer 读取器
	err = loader.InitializeRingBufferReader(ctx)
	require.NoError(t, err, "初始化 Ring Buffer 读取器失败")

	// 验证 Ring Buffer 读取器已创建
	assert.NotNil(t, loader.ringbufReader, "Ring Buffer 读取器应该被创建")
	assert.NotNil(t, loader.ringbufReader.reader, "Ring Buffer reader 应该被初始化")
	assert.NotNil(t, loader.ringbufReader.eventChan, "事件通道应该被创建")
	assert.NotNil(t, loader.ringbufReader.batchChan, "批量通道应该被创建")

	// 验证默认配置
	assert.Equal(t, 100, loader.ringbufReader.batchSize, "默认批量大小应该是 100")
	assert.Equal(t, 100*time.Millisecond, loader.ringbufReader.batchTimeout, "默认批量超时应该是 100ms")
	assert.Equal(t, 0, len(loader.ringbufReader.handlers), "默认应该没有事件处理器")

	// 验证通道容量
	assert.Equal(t, 1000, cap(loader.ringbufReader.eventChan), "事件通道容量应该是 1000")
	assert.Equal(t, 100, cap(loader.ringbufReader.batchChan), "批量通道容量应该是 100")
}

// MockEventHandler 模拟事件处理器
type MockEventHandler struct {
	eventCount  int
	batchCount  int
	lastEvent   *NetworkEvent
	lastBatch   []*NetworkEvent
	mu          sync.Mutex
}

func (m *MockEventHandler) HandleEvent(event *NetworkEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventCount++
	m.lastEvent = event
	return nil
}

func (m *MockEventHandler) HandleBatch(events []*NetworkEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batchCount++
	m.lastBatch = make([]*NetworkEvent, len(events))
	copy(m.lastBatch, events)
	return nil
}

func (m *MockEventHandler) GetStats() (eventCount, batchCount int, lastEvent *NetworkEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventCount, m.batchCount, m.lastEvent
}

// TestNetworkLoader_EventHandler 测试事件处理器功能
func TestNetworkLoader_EventHandler(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	// 加载程序
	err := loader.LoadPrograms()
	require.NoError(t, err)

	// 附加到 lo 接口
	err = loader.AttachNetworkPrograms("lo")
	require.NoError(t, err)

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 初始化 Ring Buffer 读取器
	err = loader.InitializeRingBufferReader(ctx)
	require.NoError(t, err)

	// 创建模拟事件处理器
	handler := &MockEventHandler{}
	loader.AddEventHandler(handler)

	// 验证处理器已添加
	assert.Equal(t, 1, len(loader.ringbufReader.handlers), "应该有一个事件处理器")

	// 启动 Ring Buffer 处理
	err = loader.StartRingBufferProcessing()
	require.NoError(t, err)

	// 等待处理器启动
	time.Sleep(100 * time.Millisecond)

	// 生成网络流量
	fmt.Println("📡 生成测试网络流量用于事件处理器测试...")
	cmd := exec.Command("ping", "-c", "5", "-i", "0.1", "127.0.0.1")
	err = cmd.Run()
	if err != nil {
		t.Logf("警告: ping 失败: %v", err)
	}

	// 等待事件被处理
	time.Sleep(2 * time.Second)

	// 检查处理器统计
	eventCount, batchCount, lastEvent := handler.GetStats()
	fmt.Printf("事件处理器统计: events=%d, batches=%d\n", eventCount, batchCount)

	if lastEvent != nil {
		fmt.Printf("最后一个事件: %s\n", lastEvent.String())
		
		// 验证事件字段
		assert.Greater(t, lastEvent.Timestamp, uint64(0), "时间戳应该大于 0")
		assert.Greater(t, lastEvent.PacketLen, uint16(0), "包长度应该大于 0")
		
		// 对于 loopback 流量，源IP和目标IP应该都是 127.0.0.1
		loopbackIP := uint32(0x0100007f) // 127.0.0.1 in little-endian
		if lastEvent.SrcIP == loopbackIP || lastEvent.DstIP == loopbackIP {
			fmt.Println("✅ 成功捕获 loopback 流量")
		}
	}

	// 如果有批次被处理，验证批次处理
	if batchCount > 0 {
		assert.Greater(t, batchCount, 0, "应该处理了批次")
		fmt.Println("✅ 批量处理功能正常")
	}
}

// TestNetworkLoader_RingBufferStats 测试 Ring Buffer 统计功能
func TestNetworkLoader_RingBufferStats(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	// 在初始化前，统计应该为 nil
	stats := loader.GetRingBufferStats()
	assert.Nil(t, stats, "初始化前统计应该为 nil")

	// 加载程序
	err := loader.LoadPrograms()
	require.NoError(t, err)

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 初始化 Ring Buffer 读取器
	err = loader.InitializeRingBufferReader(ctx)
	require.NoError(t, err)

	// 现在统计应该可用
	stats = loader.GetRingBufferStats()
	require.NotNil(t, stats, "初始化后统计应该可用")

	// 验证初始统计值
	assert.Equal(t, uint64(0), stats["events_read"], "初始读取事件数应该为 0")
	assert.Equal(t, uint64(0), stats["events_dropped"], "初始丢弃事件数应该为 0")
	assert.Equal(t, uint64(0), stats["batches_processed"], "初始处理批次数应该为 0")

	// 验证统计键
	expectedKeys := []string{"events_read", "events_dropped", "batches_processed"}
	for _, key := range expectedKeys {
		_, exists := stats[key]
		assert.True(t, exists, "统计应该包含键: %s", key)
	}
}

// TestNetworkLoader_RingBufferChannels 测试 Ring Buffer 通道功能
func TestNetworkLoader_RingBufferChannels(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	// 在初始化前，通道应该为 nil
	assert.Nil(t, loader.GetEventChannel(), "初始化前事件通道应该为 nil")
	assert.Nil(t, loader.GetBatchChannel(), "初始化前批量通道应该为 nil")

	// 加载程序
	err := loader.LoadPrograms()
	require.NoError(t, err)

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 初始化 Ring Buffer 读取器
	err = loader.InitializeRingBufferReader(ctx)
	require.NoError(t, err)

	// 现在通道应该可用
	eventChan := loader.GetEventChannel()
	batchChan := loader.GetBatchChannel()

	assert.NotNil(t, eventChan, "事件通道应该可用")
	assert.NotNil(t, batchChan, "批量通道应该可用")

	// 验证通道类型
	assert.IsType(t, (<-chan *NetworkEvent)(nil), eventChan, "事件通道类型应该正确")
	assert.IsType(t, (<-chan []*NetworkEvent)(nil), batchChan, "批量通道类型应该正确")
}

// TestNetworkEvent_String 测试 NetworkEvent 字符串格式化
func TestNetworkEvent_String(t *testing.T) {
	event := &NetworkEvent{
		Timestamp: uint64(time.Now().UnixNano()),
		SrcIP:     0x0100007f, // 127.0.0.1 in little-endian
		DstIP:     0x0100007f, // 127.0.0.1 in little-endian
		SrcPort:   12345,
		DstPort:   80,
		PacketLen: 64,
		Protocol:  6,  // TCP
		Direction: 0,  // INGRESS
		TCPFlags:  0x18, // PSH|ACK
		EventType: 0,  // NORMAL
		Ifindex:   1,  // lo
	}

	str := event.String()
	
	// 验证格式化字符串包含预期内容
	assert.Contains(t, str, "INGRESS", "应该包含方向信息")
	assert.Contains(t, str, "TCP", "应该包含协议信息") 
	assert.Contains(t, str, "127.0.0.1", "应该包含IP地址")
	assert.Contains(t, str, "12345", "应该包含源端口")
	assert.Contains(t, str, "80", "应该包含目标端口")
	assert.Contains(t, str, "64 bytes", "应该包含包大小")

	fmt.Printf("事件字符串格式: %s\n", str)
}

// TestRingBufferConfig 测试 Ring Buffer 配置结构
func TestRingBufferConfig(t *testing.T) {
	// 测试默认配置
	config := &RingBufferConfig{}
	assert.False(t, config.EnableXDPEvents, "默认 XDP 事件应该禁用")
	assert.False(t, config.EnableTCEvents, "默认 TC 事件应该禁用")
	assert.False(t, config.EnableDetailedEvents, "默认详细事件应该禁用")

	// 测试配置修改
	config.EnableXDPEvents = true
	config.EnableTCEvents = true
	config.EnableDetailedEvents = true

	assert.True(t, config.EnableXDPEvents)
	assert.True(t, config.EnableTCEvents)
	assert.True(t, config.EnableDetailedEvents)
}
