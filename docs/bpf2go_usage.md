# bpf2go 使用指南

本项目现在支持使用 `bpf2go` 工具自动生成类型安全的 eBPF Go 绑定代码。

## 🎯 优势

- **类型安全**: 自动生成的 Go 结构体与 C 结构体完全匹配
- **编译时检查**: eBPF 程序在生成时就会被编译验证
- **自动化**: 无需手动管理对象文件
- **强类型 API**: Map 操作有类型检查

## 🚀 快速开始

### 1. 安装依赖

```bash
# 安装 clang 和相关工具
make install-system-deps

# 或手动安装
sudo apt-get install clang llvm libbpf-dev
```

### 2. 生成 bpf2go 代码

```bash
# 自动生成 Go 绑定代码
make generate-bpf
```

这会在 `pkg/ebpf/` 目录下生成以下文件：
- `networkmonitor_bpfeb.go` - big-endian 版本
- `networkmonitor_bpfel.go` - little-endian 版本
- `networkmonitor_bpfel.o` - 编译好的 eBPF 对象文件

### 3. 构建并运行示例

```bash
# 构建 TC 监控示例
make build-bpf2go

# 运行示例（需要 root 权限）
sudo ./bin/tc_monitor_bpf2go eth0
```

### 4. 示例输出

```
🔄 Loading eBPF programs...
✅ NetworkMonitor objects loaded successfully
📋 Loaded programs: XDP=true, TC_Egress=true, TC_Ingress=true
🔗 Attaching to interface eth0 (index: 2)
✅ XDP program attached to eth0
💡 TC egress program available (manual setup required):
   sudo tc qdisc add dev eth0 clsact
   sudo tc filter add dev eth0 egress bpf object-file <compiled.o> section tc
✅ TC monitoring started on interface eth0
📊 Monitoring network traffic statistics...
Press Ctrl+C to stop

📊 Starting statistics monitoring...

============================================================
📈 Traffic Statistics [17:20:15]
============================================================

🌐 Global Statistics:
  📥 RX: 1.2K packets, 85.4 KB
  📤 TX: 856 packets, 45.2 KB
  📊 Total: 2.1K packets, 130.6 KB
  📏 Average packet size: 62 bytes

🔀 TC Device Statistics:
  📡 Interface 2:
    📥 Ingress: 1.2K packets, 85.4 KB
    📤 Egress:  856 packets, 45.2 KB

🌊 Top Flow Statistics:
  1. TCP 192.168.1.100:22 -> 192.168.1.1:54321 (450 packets)
  2. UDP 192.168.1.100:53 -> 8.8.8.8:53 (123 packets)
  3. TCP 192.168.1.100:80 -> 192.168.1.1:12345 (89 packets)
```

## 📁 文件结构

```
pkg/ebpf/
├── bpf2go_loader.go              # bpf2go 加载器
├── embedded_loader.go            # 传统嵌入式加载器（已弃用）
├── networkmonitor_bpfeb.go       # 自动生成：big-endian
├── networkmonitor_bpfel.go       # 自动生成：little-endian
└── networkmonitor_bpfel.o        # 自动生成：eBPF 对象文件

examples/
└── tc_monitor_example.go         # 使用 bpf2go 的示例

ebpf/network/
└── monitor.c                     # eBPF C 源码（包含 go:generate 指令）
```

## 🔧 开发工作流

### 1. 修改 eBPF 程序

编辑 `ebpf/network/monitor.c` 文件，添加或修改 eBPF 程序逻辑。

### 2. 重新生成代码

```bash
# 重新生成 Go 绑定
make generate-bpf

# 重新构建
make build-bpf2go
```

### 3. 测试

```bash
# 运行测试
sudo ./bin/tc_monitor_bpf2go <interface_name>
```

## 🎛️ 高级配置

### 自定义编译选项

修改 `ebpf/network/monitor.c` 中的 `go:generate` 指令：

```c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//    -cc clang \
//    -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" \
//    --target=amd64 \
//    NetworkMonitor monitor.c
```

### 添加新的 Map 类型

在 `monitor.c` 中添加新的 Map 定义，然后重新生成：

```c
struct {
    __u32 type;
    __u32 max_entries;
    __u32 *key;
    struct my_struct *value;
} my_new_map SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 1024,
};
```

生成后，在 Go 代码中访问：

```go
// 访问新的 Map
myMap := loader.objs.MyNewMap
var key uint32 = 1
var value MyStruct
err := myMap.Lookup(key, &value)
```

## 🐛 故障排除

### 1. 生成失败

```bash
# 检查 clang 是否安装
clang --version

# 检查 bpf2go 工具
go run github.com/cilium/ebpf/cmd/bpf2go --help
```

### 2. 编译错误

```bash
# 手动编译测试
cd ebpf/network
clang -O2 -target bpf -c monitor.c -o monitor.o
```

### 3. 运行时错误

```bash
# 检查内核版本（需要 4.15+）
uname -r

# 检查 eBPF 支持
cat /proc/kallsyms | grep bpf

# 检查权限
sudo -v
```

## 📚 相关资源

- [eBPF Go 库文档](https://pkg.go.dev/github.com/cilium/ebpf)
- [bpf2go 工具文档](https://github.com/cilium/ebpf/tree/master/cmd/bpf2go)
- [eBPF 开发指南](https://docs.kernel.org/bpf/)
