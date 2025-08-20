package agent

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/your-org/kube-net-probe/pkg/collector"
	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

// Config 代理配置
type Config struct {
	NodeName     string
	ManagerAddr  string
	MetricsAddr  string
	EBPFPrograms []string
}

// Agent 代表节点上的监控代理
type Agent struct {
	config        *Config
	ebpfManager   *ebpf.Manager
	dataCollector *collector.Manager
	metricsServer *http.Server
	mu            sync.RWMutex
	running       bool
}

// New 创建新的代理实例
func New(config *Config) (*Agent, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// 自动检测节点名称
	if config.NodeName == "" {
		config.NodeName = getNodeName()
	}

	agent := &Agent{
		config: config,
	}

	// 初始化 eBPF 管理器
	agent.ebpfManager = ebpf.NewManager()

	// 初始化数据收集器
	agent.dataCollector = collector.NewManager()

	return agent, nil
}

// Run 运行代理
func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent is already running")
	}
	a.running = true
	a.mu.Unlock()

	klog.InfoS("Starting KubeNetProbe agent", "node", a.config.NodeName)

	// 加载 eBPF 程序
	if err := a.loadEBPFPrograms(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// 启动数据收集器
	go func() {
		if err := a.dataCollector.Start(ctx); err != nil {
			klog.ErrorS(err, "Data collector failed")
		}
	}()

	// 启动指标服务器
	if err := a.startMetricsServer(); err != nil {
		return fmt.Errorf("failed to start metrics server: %w", err)
	}

	// 等待上下文取消
	<-ctx.Done()

	klog.InfoS("Agent context cancelled, shutting down")
	return nil
}

// Shutdown 优雅关闭代理
func (a *Agent) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	klog.InfoS("Shutting down agent")

	var lastErr error

	// 关闭指标服务器
	if a.metricsServer != nil {
		if err := a.metricsServer.Shutdown(ctx); err != nil {
			lastErr = err
			klog.ErrorS(err, "Failed to shutdown metrics server")
		}
	}

	// 关闭 eBPF 管理器
	if err := a.ebpfManager.Close(); err != nil {
		lastErr = err
		klog.ErrorS(err, "Failed to close eBPF manager")
	}

	a.running = false
	klog.InfoS("Agent shutdown completed")

	return lastErr
}

// loadEBPFPrograms 加载 eBPF 程序
func (a *Agent) loadEBPFPrograms() error {
	klog.InfoS("Loading eBPF programs", "programs", a.config.EBPFPrograms)

	for _, programName := range a.config.EBPFPrograms {
		spec, err := a.getEBPFProgramSpec(programName)
		if err != nil {
			return fmt.Errorf("failed to get program spec for %s: %w", programName, err)
		}

		if err := a.ebpfManager.LoadProgram(programName, spec); err != nil {
			return fmt.Errorf("failed to load program %s: %w", programName, err)
		}

		klog.InfoS("eBPF program loaded successfully", "program", programName)
	}

	// 注册数据收集器
	if err := a.registerCollectors(); err != nil {
		return fmt.Errorf("failed to register collectors: %w", err)
	}

	return nil
}

// getEBPFProgramSpec 获取 eBPF 程序规范
func (a *Agent) getEBPFProgramSpec(programName string) (*ebpf.ProgramSpec, error) {
	switch programName {
	case "network":
		return &ebpf.ProgramSpec{
			Name:       "network_monitor",
			Type:       ebpf.ProgramTypeXDP,
			ObjectFile: "/etc/ebpf/network-monitor.o",
			Section:    "xdp",
			AttachTo:   "eth0", // 应该动态检测网络接口
		}, nil
	case "security":
		return &ebpf.ProgramSpec{
			Name:       "security_monitor",
			Type:       ebpf.ProgramTypeKprobe,
			ObjectFile: "/etc/ebpf/security-monitor.o",
			Section:    "kprobe/tcp_v4_connect",
			AttachTo:   "tcp_v4_connect",
		}, nil
	case "performance":
		return &ebpf.ProgramSpec{
			Name:       "performance_monitor",
			Type:       ebpf.ProgramTypeTracepoint,
			ObjectFile: "/etc/ebpf/performance-monitor.o",
			Section:    "tracepoint/net/netif_receive_skb",
			AttachTo:   "netif_receive_skb",
		}, nil
	default:
		return nil, fmt.Errorf("unknown program: %s", programName)
	}
}

// registerCollectors 注册数据收集器
func (a *Agent) registerCollectors() error {
	// 注册网络收集器
	networkCollector := collector.NewNetworkCollector(a.ebpfManager)
	if err := a.dataCollector.RegisterCollector(networkCollector); err != nil {
		return fmt.Errorf("failed to register network collector: %w", err)
	}

	// TODO: 注册其他收集器（安全、性能等）

	return nil
}

// startMetricsServer 启动指标服务器
func (a *Agent) startMetricsServer() error {
	mux := http.NewServeMux()

	// 健康检查端点
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// 就绪检查端点
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	// 指标端点
	mux.HandleFunc("/metrics", a.handleMetrics)

	a.metricsServer = &http.Server{
		Addr:    a.config.MetricsAddr,
		Handler: mux,
	}

	go func() {
		klog.InfoS("Starting metrics server", "addr", a.config.MetricsAddr)
		if err := a.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.ErrorS(err, "Metrics server failed")
		}
	}()

	return nil
}

// handleMetrics 处理指标请求
func (a *Agent) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := a.dataCollector.GetAllMetrics()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get metrics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// 简化的指标输出
	response := fmt.Sprintf(`{
		"node": "%s",
		"timestamp": %d,
		"metrics": %v
	}`, a.config.NodeName, time.Now().Unix(), metrics)

	w.Write([]byte(response))
}

// getNodeName 获取节点名称
func getNodeName() string {
	// 这里应该从环境变量或 Kubernetes API 获取
	// 现在返回默认值
	return "unknown-node"
}
