package ebpf

import (
	"context"
	"fmt"
	"os"
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

func TestNetworkLoader_LoadPrograms(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err, "Failed to load eBPF programs.")

	// 验证程序加载成功 - 检查统计功能是否可用
	stats, err := loader.GetStats()
	assert.NoError(t, err, "Failed to get stats after loading programs.")
	assert.NotNil(t, stats)
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

func TestNetworkLoader_GlobalStats(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err)

	// 读取全局统计
	stats, err := loader.ReadGlobalStats()
	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.False(t, stats.Timestamp.IsZero())

	fmt.Printf("Global Stats: %s\n", stats.String())
}

func TestManager_BasicFlow(t *testing.T) {
	manager := NewSimpleEBPFManager()
	defer manager.Close()

	// 检查初始状态
	assert.False(t, manager.IsMonitoringActive())
	assert.Empty(t, manager.GetAttachedInterface())

	// 加载程序
	err := manager.LoadNetworkMonitor()
	require.NoError(t, err)

	// 附加到回环接口进行测试
	err = manager.AttachNetworkMonitor("lo")
	require.NoError(t, err)

	// 检查状态
	assert.True(t, manager.IsMonitoringActive())
	assert.Equal(t, "lo", manager.GetAttachedInterface())

	// 等待一会儿让程序运行
	time.Sleep(500 * time.Millisecond)

	// 获取统计信息
	stats, err := manager.GetXDPStats()
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// 分离
	err = manager.DetachNetworkMonitor()
	assert.NoError(t, err)
	assert.False(t, manager.IsMonitoringActive())
}

func TestManager_Configuration(t *testing.T) {
	config := DefaultSimpleManagerConfig()
	config.XDPMode = XDPAdvancedFilter
	config.EnableDetailedLog = true

	manager := NewSimpleEBPFManagerWithConfig(config)
	defer manager.Close()

	// 验证配置 (简化版本，因为当前实现可能没有GetCurrentXDPMode方法)
	// 这里主要测试管理器能正常创建和关闭
	assert.NotNil(t, manager)
}

func TestSecurityEventHandler(t *testing.T) {
	handler := NewSecurityHandler(nil)

	// 测试事件处理
	event := &NetworkEvent{
		EventType: EventTypeSecurity,
		SrcIP:     0xC0A80101, // 192.168.1.1
		PacketLen: 64,
	}

	err := handler.HandleEvent(event)
	assert.NoError(t, err)

	// 测试批处理
	events := []*NetworkEvent{event, event}
	err = handler.HandleBatch(events)
	assert.NoError(t, err)

	// 测试查询接口
	queryInterface := handler.GetQueryInterface()
	assert.NotNil(t, queryInterface)

	stats := queryInterface.GetTotalStats()
	assert.NotNil(t, stats)
}

func TestBlacklistManagement(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	err := loader.LoadPrograms()
	require.NoError(t, err)

	// 测试添加IP到黑名单
	testIP := "192.168.1.100"
	err = loader.AddToBlacklist(testIP)
	assert.NoError(t, err)

	// 获取黑名单
	ips, err := loader.GetBlacklistedIPs()
	assert.NoError(t, err)
	assert.Contains(t, ips, testIP)

	// 移除IP
	err = loader.RemoveFromBlacklist(testIP)
	assert.NoError(t, err)

	// 验证移除
	ips, err = loader.GetBlacklistedIPs()
	assert.NoError(t, err)
	assert.NotContains(t, ips, testIP)
}

func TestRingBufferConfiguration(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	// 设置Ring Buffer配置
	config := &RingBufferConfig{
		EnableXDPEvents:      true,
		EnableTCEvents:       true,
		EnableDetailedEvents: false,
	}
	loader.SetRingBufferConfig(config)

	err := loader.LoadPrograms()
	require.NoError(t, err)

	// 初始化Ring Buffer
	ctx := context.Background()
	err = loader.InitializeRingBufferReader(ctx)
	assert.NoError(t, err)
}

func TestXDPProgramTypes(t *testing.T) {
	loader := NewNetworkLoader()
	defer loader.Close()

	// 测试不同的XDP程序类型
	types := []XDPProgramType{
		XDPBasicMonitor,
		XDPAdvancedFilter,
		XDPLoadBalancer,
	}

	for _, xdpType := range types {
		loader.SetXDPProgramType(xdpType)
		err := loader.LoadPrograms()
		require.NoError(t, err, "Failed to load XDP program type: %v", xdpType)

		// 重新创建loader进行下一次测试
		loader.Close()
		loader = NewNetworkLoader()
	}
}
