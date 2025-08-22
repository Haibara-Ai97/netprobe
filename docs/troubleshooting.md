# eBPF 编译故障排除指南

## 🔍 常见编译错误及解决方案

### 1. `fatal error: 'asm/types.h' file not found`

**问题原因**: 缺少内核开发头文件

**解决方案**:
```bash
# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r)

# CentOS/RHEL
sudo yum install kernel-devel

# Fedora
sudo dnf install kernel-devel

# 或使用我们的自动安装脚本
make install-system-deps
```

### 2. `clang: command not found`

**解决方案**:
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm

# CentOS/RHEL
sudo yum install clang llvm

# Fedora
sudo dnf install clang llvm
```

### 3. 头文件路径问题

如果仍然有头文件问题，可以尝试：

```bash
# 查找头文件位置
find /usr/include -name "types.h" 2>/dev/null

# 手动指定头文件路径
export C_INCLUDE_PATH=/usr/include/$(uname -m)-linux-gnu:$C_INCLUDE_PATH
```

### 4. 类型转换和字节序错误

**错误示例**:
```
error: incompatible integer to pointer conversion
error: result of comparison of constant 524296 with expression of type '__u16' is always true
```

**解决方案**:
```bash
# 使用修复版本
make build-ebpf-minimal

# 或手动编译修复版本
clang -O2 -target bpf -c ebpf/network/monitor_fixed.c -o bin/ebpf/network-monitor.o
```

### 5. 测试编译环境

运行编译测试脚本：
```bash
chmod +x scripts/test_compilation.sh
./scripts/test_compilation.sh
```

## 🛠️ 调试步骤

### 1. 检查系统环境
```bash
# 检查内核版本
uname -r

# 检查 clang 版本
clang --version

# 检查头文件
ls -la /usr/include/linux/

# 检查 BPF 支持
ls -la /sys/fs/bpf/
```

### 2. 验证编译环境
```bash
# 测试简单的 BPF 程序编译
echo 'int main() { return 0; }' | clang -target bpf -c -x c - -o /tmp/test.o
echo $?  # 应该返回 0
```

### 3. 手动编译测试
```bash
# 手动编译网络监控程序
clang -O2 -g -Wall -Werror \
    -D__KERNEL__ -D__BPF_TRACING__ \
    -Wno-unused-value -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-address-of-packed-member \
    -I/usr/include \
    -I/usr/include/$(uname -m)-linux-gnu \
    -target bpf \
    -c ebpf/network/monitor.c \
    -o bin/ebpf/network-monitor.o
```

## 🔧 替代方案

### 1. 使用 Docker 编译环境
```bash
# 使用官方 BPF 编译环境
docker run --rm -v $(pwd):/src -w /src \
    quay.io/cilium/clang:latest \
    clang -O2 -target bpf -c ebpf/network/monitor.c -o bin/ebpf/network-monitor.o
```

### 2. 使用预编译的头文件
下载并使用 `vmlinux.h`:
```bash
# 生成 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## 📚 相关资源

- [BPF 开发环境搭建](https://docs.cilium.io/en/latest/bpf/toolchain/)
- [内核头文件说明](https://www.kernel.org/doc/Documentation/kbuild/headers_install.txt)
- [Clang BPF 支持](https://clang.llvm.org/docs/UsersManual.html#compiling-bpf-programs)
