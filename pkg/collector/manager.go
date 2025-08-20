package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// Manager 管理所有数据收集器
type Manager struct {
	collectors map[string]Collector
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// Collector 定义数据收集器接口
type Collector interface {
	// Name 返回收集器名称
	Name() string

	// Start 启动收集器
	Start(ctx context.Context) error

	// Stop 停止收集器
	Stop() error

	// GetMetrics 获取收集的指标
	GetMetrics() (map[string]interface{}, error)
}

// NewManager 创建新的数据收集管理器
func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		collectors: make(map[string]Collector),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// RegisterCollector 注册新的收集器
func (m *Manager) RegisterCollector(collector Collector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := collector.Name()
	if _, exists := m.collectors[name]; exists {
		return fmt.Errorf("collector %s already registered", name)
	}

	m.collectors[name] = collector
	klog.InfoS("Registered collector", "name", name)
	return nil
}

// Start 实现 controller-runtime manager.Runnable 接口
func (m *Manager) Start(ctx context.Context) error {
	klog.InfoS("Starting data collector manager")

	// 启动所有收集器
	for name, collector := range m.collectors {
		go func(name string, c Collector) {
			klog.InfoS("Starting collector", "name", name)
			if err := c.Start(ctx); err != nil {
				klog.ErrorS(err, "Failed to start collector", "name", name)
			}
		}(name, collector)
	}

	// 等待上下文取消
	<-ctx.Done()

	// 停止所有收集器
	m.mu.RLock()
	var wg sync.WaitGroup
	for name, collector := range m.collectors {
		wg.Add(1)
		go func(name string, c Collector) {
			defer wg.Done()
			klog.InfoS("Stopping collector", "name", name)
			if err := c.Stop(); err != nil {
				klog.ErrorS(err, "Failed to stop collector", "name", name)
			}
		}(name, collector)
	}
	m.mu.RUnlock()

	// 等待所有收集器停止，或者超时
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		klog.InfoS("All collectors stopped")
	case <-time.After(30 * time.Second):
		klog.WarningS("Timeout waiting for collectors to stop")
	}

	return nil
}

// GetCollector 获取指定名称的收集器
func (m *Manager) GetCollector(name string) (Collector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	collector, exists := m.collectors[name]
	if !exists {
		return nil, fmt.Errorf("collector %s not found", name)
	}

	return collector, nil
}

// GetAllMetrics 获取所有收集器的指标
func (m *Manager) GetAllMetrics() (map[string]map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]map[string]interface{})

	for name, collector := range m.collectors {
		metrics, err := collector.GetMetrics()
		if err != nil {
			klog.ErrorS(err, "Failed to get metrics from collector", "name", name)
			continue
		}
		result[name] = metrics
	}

	return result, nil
}
