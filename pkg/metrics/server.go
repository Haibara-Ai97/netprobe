package metrics

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Haibara-Ai97/netprobe/pkg/collector"
)

// ServerConfig HTTP 服务器配置
type ServerConfig struct {
	Port           int           // 监听端口，默认 8081
	Path           string        // metrics 路径，默认 "/metrics"
	ReadTimeout    time.Duration // 读取超时，默认 10 秒
	WriteTimeout   time.Duration // 写入超时，默认 10 秒
	MaxHeaderBytes int           // 最大头部字节数，默认 1MB
	EnableCORS     bool          // 是否启用 CORS
	EnableGzip     bool          // 是否启用 Gzip 压缩
}

// DefaultServerConfig 返回默认服务器配置
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:           8081,
		Path:           "/metrics",
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
		EnableCORS:     true,
		EnableGzip:     true,
	}
}

// Server Prometheus metrics HTTP 服务器
type Server struct {
	config          *ServerConfig
	networkMetrics  *NetworkMetrics
	httpServer      *http.Server
	mutex           sync.RWMutex
	isRunning       bool
	requestCount    uint64
	lastRequestTime time.Time
}

// NewServer 创建新的 metrics 服务器
func NewServer(config *ServerConfig) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	return &Server{
		config:         config,
		networkMetrics: NewNetworkMetrics(),
	}
}

// UpdateMetrics 更新网络指标
func (s *Server) UpdateMetrics(stats []collector.InterfaceStats) {
	s.networkMetrics.Update(stats)
}

// Start 启动 HTTP 服务器
func (s *Server) Start(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isRunning {
		return fmt.Errorf("server is already running")
	}

	// 创建 HTTP 路由
	mux := http.NewServeMux()

	// 注册 metrics 端点
	mux.HandleFunc(s.config.Path, s.handleMetrics)

	// 注册健康检查端点
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)

	// 注册根路径，提供指引信息
	mux.HandleFunc("/", s.handleRoot)

	// 创建 HTTP 服务器
	s.httpServer = &http.Server{
		Addr:           fmt.Sprintf(":%d", s.config.Port),
		Handler:        s.wrapMiddleware(mux),
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		MaxHeaderBytes: s.config.MaxHeaderBytes,
	}

	// 启动服务器
	s.isRunning = true

	go func() {
		log.Printf("🚀 Metrics server starting on port %d", s.config.Port)
		log.Printf("📊 Metrics endpoint: http://localhost:%d%s", s.config.Port, s.config.Path)

		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ Metrics server error: %v", err)
		}
	}()

	// 等待上下文取消
	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	return nil
}

// Stop 停止 HTTP 服务器
func (s *Server) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning {
		return nil
	}

	s.isRunning = false

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("⚠️  Error shutting down metrics server: %v", err)
			return err
		}
	}

	log.Println("🛑 Metrics server stopped")
	return nil
}

// IsRunning 检查服务器是否正在运行
func (s *Server) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isRunning
}

// GetStats 获取服务器统计信息
func (s *Server) GetStats() ServerStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return ServerStats{
		IsRunning:          s.isRunning,
		Port:               s.config.Port,
		MetricsPath:        s.config.Path,
		RequestCount:       s.requestCount,
		LastRequestTime:    s.lastRequestTime,
		MetricCount:        s.networkMetrics.GetMetricCount(),
		LastCollectionTime: s.networkMetrics.GetLastCollectionTime(),
		CollectionCount:    s.networkMetrics.GetCollectionCount(),
	}
}

// ServerStats 服务器统计信息
type ServerStats struct {
	IsRunning          bool
	Port               int
	MetricsPath        string
	RequestCount       uint64
	LastRequestTime    time.Time
	MetricCount        int
	LastCollectionTime time.Time
	CollectionCount    uint64
}

// String 格式化显示服务器统计
func (ss *ServerStats) String() string {
	status := "stopped"
	if ss.IsRunning {
		status = "running"
	}

	return fmt.Sprintf(
		"Metrics Server: %s on port %d\n"+
			"  Endpoint: %s\n"+
			"  Requests: %d (last: %s)\n"+
			"  Metrics: %d (collections: %d)\n"+
			"  Last collection: %s",
		status, ss.Port, ss.MetricsPath,
		ss.RequestCount, formatTime(ss.LastRequestTime),
		ss.MetricCount, ss.CollectionCount,
		formatTime(ss.LastCollectionTime))
}

// handleMetrics 处理 metrics 请求
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.mutex.Lock()
	s.requestCount++
	s.lastRequestTime = time.Now()
	s.mutex.Unlock()

	// 设置响应头
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// 获取 Prometheus 格式的指标
	metricsOutput := s.networkMetrics.GetPrometheusFormat()

	// 如果没有数据，返回基本的健康状态
	if metricsOutput == "" {
		metricsOutput = "# HELP netprobe_up Whether the netprobe exporter is up\n" +
			"# TYPE netprobe_up gauge\n" +
			"netprobe_up 1\n"
	}

	// 写入响应
	if _, err := w.Write([]byte(metricsOutput)); err != nil {
		log.Printf("⚠️  Error writing metrics response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// handleHealth 处理健康检查请求
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats := s.GetStats()

	w.Header().Set("Content-Type", "application/json")

	healthStatus := "ok"
	statusCode := http.StatusOK

	// 检查最后收集时间，如果超过 30 秒没有收集数据，认为不健康
	if !stats.LastCollectionTime.IsZero() && time.Since(stats.LastCollectionTime) > 30*time.Second {
		healthStatus = "stale"
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)

	response := fmt.Sprintf(`{
  "status": "%s",
  "timestamp": "%s",
  "server": {
    "running": %t,
    "port": %d,
    "requests": %d,
    "metrics": %d,
    "collections": %d,
    "last_collection": "%s"
  }
}`,
		healthStatus,
		time.Now().UTC().Format(time.RFC3339),
		stats.IsRunning,
		stats.Port,
		stats.RequestCount,
		stats.MetricCount,
		stats.CollectionCount,
		stats.LastCollectionTime.UTC().Format(time.RFC3339))

	w.Write([]byte(response))
}

// handleRoot 处理根路径请求
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>NetProbe Metrics Exporter</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .status { color: #28a745; font-weight: bold; }
        .metrics { color: #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 NetProbe Metrics Exporter</h1>
        <p>NetProbe metrics exporter for Prometheus monitoring.</p>
        
        <h2>Available Endpoints</h2>
        <div class="endpoint">
            <strong>📊 Metrics:</strong> 
            <a href="%s" class="metrics">%s</a>
            <br><small>Prometheus-compatible network traffic metrics</small>
        </div>
        
        <div class="endpoint">
            <strong>💓 Health Check:</strong> 
            <a href="/health">/health</a>
            <br><small>Service health status in JSON format</small>
        </div>
        
        <h2>Current Status</h2>
        <p class="status">✅ Server is running on port %d</p>
        
        <h2>Metrics Information</h2>
        <ul>
            <li><code>netprobe_tc_packets_total</code> - Total packets processed by TC (counter)</li>
            <li><code>netprobe_tc_bytes_total</code> - Total bytes processed by TC (counter)</li>
            <li><code>netprobe_tc_packets_per_second</code> - Packet rate per second (gauge)</li>
            <li><code>netprobe_tc_bytes_per_second</code> - Byte rate per second (gauge)</li>
            <li><code>netprobe_interface_active</code> - Interface activity status (gauge)</li>
            <li><code>netprobe_up</code> - Exporter health status (gauge)</li>
        </ul>
        
        <h2>Labels</h2>
        <ul>
            <li><code>interface</code> - Network interface name (e.g., eth0, wlan0)</li>
            <li><code>ifindex</code> - Network interface index</li>
            <li><code>direction</code> - Traffic direction (ingress/egress)</li>
        </ul>
    </div>
</body>
</html>`,
		s.config.Path, s.config.Path, s.config.Port)

	w.Write([]byte(html))
}

// wrapMiddleware 包装中间件
func (s *Server) wrapMiddleware(handler http.Handler) http.Handler {
	// 日志中间件
	handler = s.loggingMiddleware(handler)

	// CORS 中间件
	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	return handler
}

// loggingMiddleware 日志中间件
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建响应写入器来捕获状态码
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// 处理请求
		next.ServeHTTP(rw, r)

		// 记录日志
		duration := time.Since(start)
		log.Printf("📊 %s %s %d %v %s",
			r.Method, r.URL.Path, rw.statusCode, duration, r.RemoteAddr)
	})
}

// corsMiddleware CORS 中间件
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter 用于捕获状态码的响应写入器
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// formatTime 格式化时间
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format("15:04:05")
}
