package collector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

// Collector 定义收集器接口
type Collector interface {
	// CollectOnce 执行一次数据收集
	CollectOnce() ([]InterfaceStats, error)
	
	// StartPeriodicCollection 启动周期性收集
	StartPeriodicCollection(ctx context.Context) <-chan CollectionResult
	
	// GetInterfaceCount 获取监控的接口数量
	GetInterfaceCount() int
	
	// SetCollectInterval 设置收集间隔
	SetCollectInterval(interval time.Duration)
}

// CollectionResult 收集结果
type CollectionResult struct {
	Stats []InterfaceStats
	Error error
	Timestamp time.Time
}

// Manager 收集器管理器
type Manager struct {
	tcCollector *TCCollector
	mutex       sync.RWMutex
	isRunning   bool
	cancelFunc  context.CancelFunc
}

// NewManager 创建新的收集器管理器
func NewManager(ebpfManager *ebpf.Manager) *Manager {
	return &Manager{
		tcCollector: NewTCCollector(ebpfManager),
	}
}

// GetTCCollector 获取 TC 收集器
func (m *Manager) GetTCCollector() *TCCollector {
	return m.tcCollector
}

// SetCollectInterval 设置所有收集器的收集间隔
func (m *Manager) SetCollectInterval(interval time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if m.tcCollector != nil {
		m.tcCollector.SetCollectInterval(interval)
	}
}

// Start 启动所有收集器
func (m *Manager) Start(ctx context.Context) <-chan CollectionResult {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if m.isRunning {
		log.Println("Collection manager is already running")
		return nil
	}
	
	// 创建可取消的上下文
	childCtx, cancel := context.WithCancel(ctx)
	m.cancelFunc = cancel
	m.isRunning = true
	
	resultChan := make(chan CollectionResult, 10)
	
	go func() {
		defer close(resultChan)
		defer func() {
			m.mutex.Lock()
			m.isRunning = false
			m.mutex.Unlock()
		}()
		
		// 启动 TC 收集器
		tcResultChan := m.startTCCollection(childCtx)
		
		for {
			select {
			case <-childCtx.Done():
				log.Println("Collection manager stopped")
				return
				
			case tcResult, ok := <-tcResultChan:
				if !ok {
					log.Println("TC collection channel closed")
					return
				}
				
				// 转发结果
				select {
				case resultChan <- tcResult:
				case <-childCtx.Done():
					return
				default:
					// 如果通道已满，记录警告但继续
					log.Println("Warning: collection result channel is full, dropping result")
				}
			}
		}
	}()
	
	return resultChan
}

// startTCCollection 启动 TC 收集
func (m *Manager) startTCCollection(ctx context.Context) <-chan CollectionResult {
	resultChan := make(chan CollectionResult, 5)
	
	go func() {
		defer close(resultChan)
		
		ticker := time.NewTicker(m.tcCollector.collectInterval)
		defer ticker.Stop()
		
		// 立即执行一次收集
		m.performTCCollection(resultChan)
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.performTCCollection(resultChan)
			}
		}
	}()
	
	return resultChan
}

// performTCCollection 执行 TC 收集
func (m *Manager) performTCCollection(resultChan chan<- CollectionResult) {
	stats, err := m.tcCollector.CollectOnce()
	result := CollectionResult{
		Stats:     stats,
		Error:     err,
		Timestamp: time.Now(),
	}
	
	select {
	case resultChan <- result:
	default:
		// 如果通道已满，记录警告
		log.Println("Warning: TC collection result channel is full")
	}
}

// Stop 停止所有收集器
func (m *Manager) Stop() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if !m.isRunning {
		return
	}
	
	if m.cancelFunc != nil {
		m.cancelFunc()
		m.cancelFunc = nil
	}
	
	log.Println("Collection manager stopped")
}

// IsRunning 检查收集器是否正在运行
func (m *Manager) IsRunning() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.isRunning
}

// GetCollectionStatus 获取收集状态
func (m *Manager) GetCollectionStatus() CollectionStatus {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	return CollectionStatus{
		IsRunning:        m.isRunning,
		InterfaceCount:   m.tcCollector.GetInterfaceCount(),
		CollectInterval:  m.tcCollector.collectInterval,
		SupportedInterfaces: m.tcCollector.GetSupportedInterfaces(),
	}
}

// CollectionStatus 收集状态
type CollectionStatus struct {
	IsRunning           bool
	InterfaceCount      int
	CollectInterval     time.Duration
	SupportedInterfaces []string
}

// String 格式化显示收集状态
func (cs *CollectionStatus) String() string {
	status := "stopped"
	if cs.IsRunning {
		status = "running"
	}
	
	return fmt.Sprintf("Collection Status: %s, Interfaces: %d, Interval: %v",
		status, cs.InterfaceCount, cs.CollectInterval)
}
