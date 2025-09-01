package metrics

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Haibara-Ai97/netprobe/pkg/collector"
	"github.com/Haibara-Ai97/netprobe/pkg/ebpf"
)

// ExporterConfig 导出器配置
type ExporterConfig struct {
	// 服务器配置
	ServerConfig *ServerConfig

	// 收集配置
	CollectInterval  time.Duration // 数据收集间隔，默认 5 秒
	InterfaceFilter  []string      // 接口名称过滤器，空表示所有接口
	EnableActiveOnly bool          // 是否只导出活跃接口的指标

	// 其他配置
	LogLevel string // 日志级别：debug, info, warn, error
}

// DefaultExporterConfig 返回默认导出器配置
func DefaultExporterConfig() *ExporterConfig {
	return &ExporterConfig{
		ServerConfig:     DefaultServerConfig(),
		CollectInterval:  5 * time.Second,
		InterfaceFilter:  nil,
		EnableActiveOnly: false,
		LogLevel:         "info",
	}
}

// Exporter Prometheus metrics 导出器
type Exporter struct {
	config           *ExporterConfig
	ebpfManager      *ebpf.SimpleEBPFManager
	collectorManager *collector.Manager
	metricsServer    *Server

	mutex     sync.RWMutex
	isRunning bool
	startTime time.Time

	// 统计信息
	totalCollections uint64
	totalErrors      uint64
	lastError        error
	lastErrorTime    time.Time
}

// NewExporter 创建新的 metrics 导出器
func NewExporter(ebpfManager *ebpf.SimpleEBPFManager, config *ExporterConfig) *Exporter {
	if config == nil {
		config = DefaultExporterConfig()
	}

	return &Exporter{
		config:           config,
		ebpfManager:      ebpfManager,
		collectorManager: collector.NewManager(ebpfManager),
		metricsServer:    NewServer(config.ServerConfig),
	}
}

// Start 启动导出器
func (e *Exporter) Start(ctx context.Context) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.isRunning {
		return fmt.Errorf("exporter is already running")
	}

	e.isRunning = true
	e.startTime = time.Now()

	log.Println("🚀 Starting NetProbe metrics exporter...")

	// 设置收集间隔
	e.collectorManager.SetCollectInterval(e.config.CollectInterval)

	// 启动 HTTP 服务器
	if err := e.metricsServer.Start(ctx); err != nil {
		e.isRunning = false
		return fmt.Errorf("failed to start metrics server: %w", err)
	}

	// 启动数据收集
	resultChan := e.collectorManager.Start(ctx)
	if resultChan == nil {
		e.isRunning = false
		return fmt.Errorf("failed to start collector manager")
	}

	// 启动结果处理协程
	go e.processCollectionResults(ctx, resultChan)

	log.Printf("✅ NetProbe exporter started successfully")
	log.Printf("📊 Metrics available at: http://localhost:%d%s",
		e.config.ServerConfig.Port, e.config.ServerConfig.Path)
	log.Printf("💓 Health check at: http://localhost:%d/health",
		e.config.ServerConfig.Port)

	return nil
}

// Stop 停止导出器
func (e *Exporter) Stop() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.isRunning {
		return nil
	}

	log.Println("🛑 Stopping NetProbe metrics exporter...")

	// 停止收集器
	e.collectorManager.Stop()

	// 停止 HTTP 服务器
	if err := e.metricsServer.Stop(); err != nil {
		log.Printf("⚠️  Error stopping metrics server: %v", err)
	}

	e.isRunning = false

	log.Println("✅ NetProbe exporter stopped")
	return nil
}

// processCollectionResults 处理收集结果
func (e *Exporter) processCollectionResults(ctx context.Context, resultChan <-chan collector.CollectionResult) {
	defer log.Println("📊 Collection result processor stopped")

	for {
		select {
		case <-ctx.Done():
			return

		case result, ok := <-resultChan:
			if !ok {
				log.Println("📊 Collection result channel closed")
				return
			}

			e.handleCollectionResult(result)
		}
	}
}

// handleCollectionResult 处理单个收集结果
func (e *Exporter) handleCollectionResult(result collector.CollectionResult) {
	e.mutex.Lock()
	e.totalCollections++

	if result.Error != nil {
		e.totalErrors++
		e.lastError = result.Error
		e.lastErrorTime = result.Timestamp
		e.mutex.Unlock()

		log.Printf("❌ Collection error: %v", result.Error)
		return
	}
	e.mutex.Unlock()

	// 过滤接口（如果配置了过滤器）
	stats := result.Stats
	if len(e.config.InterfaceFilter) > 0 {
		stats = collector.FilterInterfacesByName(stats, e.config.InterfaceFilter)
	}

	// 过滤活跃接口（如果启用）
	if e.config.EnableActiveOnly {
		stats = collector.FilterActiveInterfaces(stats)
	}

	// 更新 metrics
	e.metricsServer.UpdateMetrics(stats)

	// 记录调试信息
	if e.config.LogLevel == "debug" {
		summary := collector.SummarizeCollection(stats, 3)
		log.Printf("📈 Collection completed: %d interfaces, %d active",
			summary.TotalInterfaces, summary.ActiveInterfaces)
	}
}

// GetStatus 获取导出器状态
func (e *Exporter) GetStatus() ExporterStatus {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	collectorStatus := e.collectorManager.GetCollectionStatus()
	serverStats := e.metricsServer.GetStats()

	return ExporterStatus{
		IsRunning:        e.isRunning,
		StartTime:        e.startTime,
		Uptime:           time.Since(e.startTime),
		TotalCollections: e.totalCollections,
		TotalErrors:      e.totalErrors,
		LastError:        e.lastError,
		LastErrorTime:    e.lastErrorTime,

		// 收集器状态
		CollectorStatus: collectorStatus,

		// 服务器状态
		ServerStats: serverStats,

		// 配置信息
		Config: *e.config,
	}
}

// ExporterStatus 导出器状态
type ExporterStatus struct {
	IsRunning        bool
	StartTime        time.Time
	Uptime           time.Duration
	TotalCollections uint64
	TotalErrors      uint64
	LastError        error
	LastErrorTime    time.Time

	CollectorStatus collector.CollectionStatus
	ServerStats     ServerStats
	Config          ExporterConfig
}

// String 格式化显示导出器状态
func (es *ExporterStatus) String() string {
	status := "stopped"
	if es.IsRunning {
		status = "running"
	}

	uptime := es.Uptime.Truncate(time.Second)
	errorRate := float64(0)
	if es.TotalCollections > 0 {
		errorRate = float64(es.TotalErrors) / float64(es.TotalCollections) * 100
	}

	return fmt.Sprintf(
		"NetProbe Exporter Status: %s\n"+
			"  Uptime: %v (since %s)\n"+
			"  Collections: %d (errors: %d, rate: %.1f%%)\n"+
			"  %s\n"+
			"  %s",
		status,
		uptime, es.StartTime.Format("15:04:05"),
		es.TotalCollections, es.TotalErrors, errorRate,
		es.CollectorStatus.String(),
		es.ServerStats.String())
}

// GetMetricsURL 获取 metrics URL
func (e *Exporter) GetMetricsURL() string {
	return fmt.Sprintf("http://localhost:%d%s",
		e.config.ServerConfig.Port, e.config.ServerConfig.Path)
}

// GetHealthURL 获取健康检查 URL
func (e *Exporter) GetHealthURL() string {
	return fmt.Sprintf("http://localhost:%d/health", e.config.ServerConfig.Port)
}

// IsRunning 检查导出器是否正在运行
func (e *Exporter) IsRunning() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.isRunning
}

// WaitForReady 等待导出器准备就绪
func (e *Exporter) WaitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if e.IsRunning() && e.metricsServer.IsRunning() {
			// 等待至少一次数据收集
			status := e.GetStatus()
			if status.TotalCollections > 0 || status.ServerStats.MetricCount > 0 {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("exporter not ready within %v", timeout)
}
