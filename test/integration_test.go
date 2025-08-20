package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/your-org/kube-net-probe/pkg/ebpf"
)

func TestMain(m *testing.M) {
	// 检查测试环境
	if !ebpf.IsSupported() {
		fmt.Println("Warning: eBPF is not supported in test environment, skipping eBPF tests")
	}

	code := m.Run()
	os.Exit(code)
}

func TestEBPFSupport(t *testing.T) {
	supported := ebpf.IsSupported()
	t.Logf("eBPF support: %v", supported)

	if !supported {
		t.Skip("eBPF not supported, skipping test")
	}
}

func TestEBPFManager(t *testing.T) {
	if !ebpf.IsSupported() {
		t.Skip("eBPF not supported, skipping test")
	}

	manager := ebpf.NewManager()
	if manager == nil {
		t.Fatal("Failed to create eBPF manager")
	}

	// 测试程序规格
	spec := &ebpf.ProgramSpec{
		Name:       "test_program",
		Type:       ebpf.ProgramTypeSocketFilter,
		ObjectFile: "/tmp/test.o", // 这个文件不存在，会失败
		Section:    "socket",
		AttachTo:   "",
	}

	// 尝试加载程序（预期会失败）
	err := manager.LoadProgram("test", spec)
	if err == nil {
		t.Error("Expected program loading to fail with non-existent object file")
	}

	// 清理
	manager.Close()
}

func TestCollectorManager(t *testing.T) {
	// 这里会添加数据收集器的测试
	t.Skip("Collector tests not implemented yet")
}

func TestAnalyzerManager(t *testing.T) {
	// 这里会添加数据分析器的测试
	t.Skip("Analyzer tests not implemented yet")
}
