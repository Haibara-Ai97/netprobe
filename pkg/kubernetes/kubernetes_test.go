package kubernetes_test

import (
	"testing"
	"time"

	"github.com/Haibara-Ai97/netprobe/pkg/kubernetes"
	"github.com/stretchr/testify/assert"
)

func TestK8sNetworkIntegrator(t *testing.T) {
	// 注意: 这个测试需要真实的Kubernetes集群
	// 在CI环境中可能需要跳过
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 创建集成器 (使用默认kubeconfig)
	integrator, err := kubernetes.NewK8sNetworkIntegrator("")
	if err != nil {
		t.Skipf("Failed to create integrator (no k8s cluster?): %v", err)
		return
	}
	defer integrator.Stop()

	// 启动集成器
	err = integrator.Start()
	if err != nil {
		t.Skipf("Failed to start integrator: %v", err)
		return
	}

	// 等待初始化完成
	time.Sleep(2 * time.Second)

	// 测试获取集群信息
	clusterInfo, err := integrator.GetClusterInfo()
	assert.NoError(t, err)
	assert.NotNil(t, clusterInfo)
	assert.Greater(t, clusterInfo.NodeCount, 0)

	// 测试获取拓扑信息
	topology := integrator.GetTopology()
	assert.NotNil(t, topology)

	// 测试处理VXLAN事件
	integrator.ProcessVXLANEvent("10.244.0.1", "10.244.1.1", 8080, 80, 6, 1, 1500)

	// 测试处理网络事件
	integrator.ProcessNetworkEvent("10.244.0.1", "10.244.1.1", 8080, 80, 6, 1500, "egress", "TC_EGRESS")

	// 等待事件处理
	time.Sleep(1 * time.Second)

	// 测试获取流量统计
	stats := integrator.GetTrafficStats()
	assert.NotNil(t, stats)
	assert.Greater(t, stats.TotalFlows, uint64(0))

	// 测试获取Top Talkers
	topTalkers := integrator.GetTopTalkers(5)
	assert.NotNil(t, topTalkers)
}

func TestTrafficAnalyzer(t *testing.T) {
	// 创建模拟的元数据管理器
	client, err := kubernetes.NewClient("")
	if err != nil {
		t.Skip("No kubernetes client available")
		return
	}

	metadataManager := kubernetes.NewMetadataManager(client)
	analyzer := kubernetes.NewTrafficAnalyzer(metadataManager)

	// 测试分析VXLAN流量
	flow := analyzer.AnalyzeVXLANTraffic("10.244.0.1", "10.244.1.1", 8080, 80, 6, 1)
	assert.NotNil(t, flow)
	assert.Equal(t, "10.244.0.1", flow.SrcIP)
	assert.Equal(t, "10.244.1.1", flow.DstIP)
	assert.Equal(t, uint32(1), flow.VNI)

	// 测试获取统计信息
	stats := analyzer.GetStats()
	assert.NotNil(t, stats)
	assert.Equal(t, uint64(1), stats.TotalFlows)
}

func TestUtilityFunctions(t *testing.T) {
	// 测试IP验证
	assert.True(t, kubernetes.ValidateIPAddress("192.168.1.1"))
	assert.False(t, kubernetes.ValidateIPAddress("invalid-ip"))

	// 测试CIDR验证
	assert.True(t, kubernetes.ValidateCIDR("10.244.0.0/16"))
	assert.False(t, kubernetes.ValidateCIDR("invalid-cidr"))

	// 测试私有IP检查
	assert.True(t, kubernetes.IsPrivateIP("10.0.0.1"))
	assert.True(t, kubernetes.IsPrivateIP("192.168.1.1"))
	assert.False(t, kubernetes.IsPrivateIP("8.8.8.8"))

	// 测试VXLAN流量检查
	assert.True(t, kubernetes.IsVXLANTraffic(4789))
	assert.True(t, kubernetes.IsVXLANTraffic(8472))
	assert.False(t, kubernetes.IsVXLANTraffic(80))

	// 测试格式化函数
	assert.Equal(t, "1.0 KB", kubernetes.FormatBytes(1024))
	assert.Equal(t, "1.0 MB", kubernetes.FormatBytes(1024*1024))

	// 测试协议名称获取
	assert.Equal(t, "TCP", kubernetes.GetProtocolName(6))
	assert.Equal(t, "UDP", kubernetes.GetProtocolName(17))
	assert.Equal(t, "ICMP", kubernetes.GetProtocolName(1))
}

// BenchmarkTrafficAnalysis 性能测试
func BenchmarkTrafficAnalysis(b *testing.B) {
	client, err := kubernetes.NewClient("")
	if err != nil {
		b.Skip("No kubernetes client available")
		return
	}

	metadataManager := kubernetes.NewMetadataManager(client)
	analyzer := kubernetes.NewTrafficAnalyzer(metadataManager)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.AnalyzeVXLANTraffic("10.244.0.1", "10.244.1.1", 8080, 80, 6, 1)
	}
}
