package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Haibara-Ai97/netprobe/pkg/ebpf"
)

// 简单的事件处理器
type SimpleEventHandler struct {
	eventCount  int64
	byteCount   int64
	lastDisplay time.Time
}

// HandleEvent 处理单个事件
func (h *SimpleEventHandler) HandleEvent(event *ebpf.NetworkEvent) error {
	atomic.AddInt64(&h.eventCount, 1)
	atomic.AddInt64(&h.byteCount, int64(event.PacketLen))
	return nil
}

// HandleBatch 处理批量事件
func (h *SimpleEventHandler) HandleBatch(events []*ebpf.NetworkEvent) error {
	for _, event := range events {
		atomic.AddInt64(&h.eventCount, 1)
		atomic.AddInt64(&h.byteCount, int64(event.PacketLen))
		
		// 每1000个事件显示一次详细信息
		if atomic.LoadInt64(&h.eventCount)%1000 == 0 {
			fmt.Printf("📦 Sample Event: %s\n", event.String())
		}
	}
	return nil
}

// 显示统计信息
func (h *SimpleEventHandler) displayStats() {
	events := atomic.LoadInt64(&h.eventCount)
	bytes := atomic.LoadInt64(&h.byteCount)
	
	fmt.Printf("\n📊 Ring Buffer Statistics:\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("Events Processed: %d\n", events)
	fmt.Printf("Bytes Processed:  %s\n", formatBytes(uint64(bytes)))
	
	// 计算速率
	now := time.Now()
	if !h.lastDisplay.IsZero() {
		duration := now.Sub(h.lastDisplay).Seconds()
		if duration > 0 {
			eps := float64(events) / duration // 这里是累积值，实际应该计算增量
			bps := float64(bytes) / duration
			fmt.Printf("Event Rate:       %.2f events/sec\n", eps)
			fmt.Printf("Byte Rate:        %s/sec\n", formatBytes(uint64(bps)))
		}
	}
	h.lastDisplay = now
	fmt.Printf("==========================================\n")
}

func main() {
	fmt.Println("🚀 NetProbe Ring Buffer Demo")
	fmt.Println("================================")

	// 检查参数
	interfaceName := "lo"
	if len(os.Args) > 1 {
		interfaceName = os.Args[1]
	}

	// 创建网络加载器
	loader := ebpf.NewNetworkLoader()
	defer loader.Close()

	// 配置 Ring Buffer
	config := &ebpf.RingBufferConfig{
		EnableXDPEvents:      false, // 避免重复
		EnableTCEvents:       true,  // 使用 TC 事件
		EnableDetailedEvents: true,  // 启用详细事件
	}
	loader.SetRingBufferConfig(config)

	// 加载 eBPF 程序
	if err := loader.LoadPrograms(); err != nil {
		log.Fatal("Failed to load eBPF programs:", err)
	}

	// 附加到网络接口
	if err := loader.AttachNetworkPrograms(interfaceName); err != nil {
		log.Fatal("Failed to attach programs:", err)
	}
	fmt.Printf("✅ Programs attached to interface %s\n", interfaceName)

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 初始化 Ring Buffer 读取器
	if err := loader.InitializeRingBufferReader(ctx); err != nil {
		log.Fatal("Failed to initialize ring buffer reader:", err)
	}

	// 创建事件处理器
	handler := &SimpleEventHandler{
		lastDisplay: time.Now(),
	}
	loader.AddEventHandler(handler)

	// 启动 Ring Buffer 处理
	if err := loader.StartRingBufferProcessing(); err != nil {
		log.Fatal("Failed to start ring buffer processing:", err)
	}

	// 启动统计显示
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				handler.displayStats()
				
				// 显示 Ring Buffer 内部统计
				stats := loader.GetRingBufferStats()
				if stats != nil {
					fmt.Printf("Ring Buffer Internal Stats:\n")
					fmt.Printf("  Events Read:       %d\n", stats["events_read"])
					fmt.Printf("  Events Dropped:    %d\n", stats["events_dropped"])
					fmt.Printf("  Batches Processed: %d\n", stats["batches_processed"])
					
					if stats["events_read"] > 0 {
						dropRate := float64(stats["events_dropped"]) / float64(stats["events_read"]) * 100
						fmt.Printf("  Drop Rate:         %.2f%%\n", dropRate)
					}
				}
			}
		}
	}()

	// 启动实时事件显示（可选）
	go func() {
		eventChan := loader.GetEventChannel()
		if eventChan == nil {
			return
		}

		sampleCount := 0
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-eventChan:
				sampleCount++
				// 每100个事件显示一个样本
				if sampleCount%100 == 0 {
					fmt.Printf("🔄 Realtime: %s\n", event.String())
				}
			}
		}
	}()

	// 信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("📡 Monitoring network traffic on interface %s...\n", interfaceName)
	fmt.Println("Press Ctrl+C to stop")

	// 等待信号
	<-sigChan
	fmt.Println("\n🛑 Shutting down...")
	
	// 最后显示一次统计
	handler.displayStats()
	stats := loader.GetRingBufferStats()
	if stats != nil {
		fmt.Printf("\nFinal Ring Buffer Stats:\n")
		fmt.Printf("  Total Events Read: %d\n", stats["events_read"])
		fmt.Printf("  Total Events Dropped: %d\n", stats["events_dropped"])
		fmt.Printf("  Total Batches: %d\n", stats["batches_processed"])
	}
}

// 格式化字节数
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
