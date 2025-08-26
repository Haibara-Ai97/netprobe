package metrics

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/your-org/kube-net-probe/pkg/collector"
	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

// SimpleExample 简单示例：启动 metrics 导出器
func SimpleExample() {
	// 1. 创建 eBPF 管理器
	ebpfManager := ebpf.NewManager()
	
	// 2. 加载网络监控程序
	if err := ebpfManager.LoadNetworkMonitor(); err != nil {
		log.Fatalf("Failed to load network monitor: %v", err)
	}
	defer ebpfManager.Close()
	
	// 3. 创建导出器（使用默认配置）
	exporter := NewExporter(ebpfManager, nil)
	
	// 4. 启动导出器
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	
	if err := exporter.Start(ctx); err != nil {
		log.Fatalf("Failed to start exporter: %v", err)
	}
	defer exporter.Stop()
	
	// 5. 等待准备就绪
	if err := exporter.WaitForReady(10 * time.Second); err != nil {
		log.Fatalf("Exporter not ready: %v", err)
	}
	
	fmt.Printf("🎉 Exporter is ready!\n")
	fmt.Printf("📊 Metrics: %s\n", exporter.GetMetricsURL())
	fmt.Printf("💓 Health: %s\n", exporter.GetHealthURL())
	
	// 6. 定期显示状态
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			fmt.Println("✅ Example completed")
			return
			
		case <-ticker.C:
			status := exporter.GetStatus()
			fmt.Printf("\n📈 Status Update:\n%s\n", status.String())
			
			// 显示最近的指标数量
			if status.ServerStats.MetricCount > 0 {
				fmt.Printf("📊 Currently exposing %d metrics\n", status.ServerStats.MetricCount)
			}
		}
	}
}

// CustomConfigExample 自定义配置示例
func CustomConfigExample() {
	// 创建自定义配置
	config := &ExporterConfig{
		ServerConfig: &ServerConfig{
			Port:         9090,  // 使用标准 Prometheus 端口
			Path:         "/metrics",
			EnableCORS:   true,
			EnableGzip:   true,
		},
		CollectInterval:  3 * time.Second,  // 3 秒收集间隔
		InterfaceFilter: []string{"eth0", "wlan0"},  // 只监控特定接口
		EnableActiveOnly: true,  // 只导出活跃接口
		LogLevel:        "debug",  // 启用调试日志
	}
	
	// 创建 eBPF 管理器
	ebpfManager := ebpf.NewManager()
	if err := ebpfManager.LoadNetworkMonitor(); err != nil {
		log.Fatalf("Failed to load network monitor: %v", err)
	}
	defer ebpfManager.Close()
	
	// 创建带自定义配置的导出器
	exporter := NewExporter(ebpfManager, config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	
	if err := exporter.Start(ctx); err != nil {
		log.Fatalf("Failed to start exporter: %v", err)
	}
	defer exporter.Stop()
	
	fmt.Printf("🚀 Custom exporter started on port %d\n", config.ServerConfig.Port)
	fmt.Printf("🔍 Monitoring interfaces: %v\n", config.InterfaceFilter)
	fmt.Printf("⚡ Active interfaces only: %v\n", config.EnableActiveOnly)
	
	// 等待上下文结束
	<-ctx.Done()
	fmt.Println("✅ Custom example completed")
}

// TestMetricsEndpoint 测试 metrics 端点
func TestMetricsEndpoint(port int, path string) error {
	url := fmt.Sprintf("http://localhost:%d%s", port, path)
	
	fmt.Printf("🧪 Testing metrics endpoint: %s\n", url)
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to get metrics: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// 检查 Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; version=0.0.4; charset=utf-8" {
		fmt.Printf("⚠️  Unexpected Content-Type: %s\n", contentType)
	}
	
	fmt.Printf("✅ Metrics endpoint is responding correctly\n")
	fmt.Printf("📊 Response size: %d bytes\n", resp.ContentLength)
	
	return nil
}

// TestHealthEndpoint 测试健康检查端点
func TestHealthEndpoint(port int) error {
	url := fmt.Sprintf("http://localhost:%d/health", port)
	
	fmt.Printf("🧪 Testing health endpoint: %s\n", url)
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to get health: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// 检查 Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		fmt.Printf("⚠️  Unexpected Content-Type: %s\n", contentType)
	}
	
	fmt.Printf("✅ Health endpoint is responding correctly\n")
	return nil
}

// ShowMetricsOutput 显示 metrics 输出示例
func ShowMetricsOutput(ebpfManager *ebpf.Manager) {
	// 创建简单的 metrics 收集器
	networkMetrics := NewNetworkMetrics()
	
	// 模拟一些数据
	stats := []collector.InterfaceStats{
		{
			InterfaceName:      "eth0",
			InterfaceIndex:     2,
			IngressPackets:     15420,
			IngressBytes:       2048576,
			EgressPackets:      12380,
			EgressBytes:        1572864,
			IngressPacketsRate: 125.5,
			IngressBytesRate:   16384.2,
			EgressPacketsRate:  98.7,
			EgressBytesRate:    12582.9,
		},
		{
			InterfaceName:      "lo",
			InterfaceIndex:     1,
			IngressPackets:     8420,
			IngressBytes:       1048576,
			EgressPackets:      8420,
			EgressBytes:        1048576,
			IngressPacketsRate: 5.2,
			IngressBytesRate:   665.6,
			EgressPacketsRate:  5.2,
			EgressBytesRate:    665.6,
		},
	}
	
	// 更新指标
	networkMetrics.Update(stats)
	
	// 显示 Prometheus 格式输出
	fmt.Println("📊 Example Prometheus Metrics Output:")
	fmt.Println("=====================================")
	fmt.Println(networkMetrics.GetPrometheusFormat())
	fmt.Println("=====================================")
	
	// 显示指标统计
	fmt.Printf("📈 Generated %d metrics for %d interfaces\n", 
		networkMetrics.GetMetricCount(), len(stats))
}

// MonitorExporter 监控导出器状态
func MonitorExporter(exporter *Exporter, duration time.Duration) {
	fmt.Printf("🔍 Monitoring exporter for %v...\n", duration)
	
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	startTime := time.Now()
	
	for {
		select {
		case <-ctx.Done():
			fmt.Printf("✅ Monitoring completed after %v\n", time.Since(startTime))
			return
			
		case <-ticker.C:
			status := exporter.GetStatus()
			
			fmt.Printf("\n[%s] Exporter Status:\n", time.Now().Format("15:04:05"))
			fmt.Printf("  Collections: %d (errors: %d)\n", 
				status.TotalCollections, status.TotalErrors)
			fmt.Printf("  Metrics: %d\n", status.ServerStats.MetricCount)
			fmt.Printf("  Requests: %d\n", status.ServerStats.RequestCount)
			
			if status.LastError != nil {
				fmt.Printf("  Last Error: %v (at %s)\n", 
					status.LastError, status.LastErrorTime.Format("15:04:05"))
			}
			
			// 测试端点可用性
			if err := TestMetricsEndpoint(
				status.Config.ServerConfig.Port, 
				status.Config.ServerConfig.Path); err != nil {
				fmt.Printf("  ⚠️  Metrics endpoint error: %v\n", err)
			}
		}
	}
}
