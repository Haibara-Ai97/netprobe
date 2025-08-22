#!/bin/bash

# 安装 eBPF 开发依赖的脚本
set -e

echo "🔧 Installing eBPF development dependencies..."

# 检测操作系统
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "❌ Cannot detect OS version"
    exit 1
fi

echo "📋 Detected OS: $OS $VER"

# 根据不同系统安装依赖
case $OS in
    "Ubuntu"*)
        echo "📦 Installing dependencies for Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y \
            clang \
            llvm \
            gcc-multilib \
            linux-headers-$(uname -r) \
            libbpf-dev \
            linux-tools-$(uname -r) \
            linux-tools-common \
            build-essential
        ;;
    "Debian"*)
        echo "📦 Installing dependencies for Debian..."
        sudo apt-get update
        sudo apt-get install -y \
            clang \
            llvm \
            gcc-multilib \
            linux-headers-$(uname -r) \
            libbpf-dev \
            build-essential
        ;;
    "CentOS"* | "Red Hat"* | "Rocky Linux"*)
        echo "📦 Installing dependencies for CentOS/RHEL..."
        sudo yum install -y \
            clang \
            llvm \
            kernel-devel \
            kernel-headers \
            gcc \
            make
        ;;
    "Fedora"*)
        echo "📦 Installing dependencies for Fedora..."
        sudo dnf install -y \
            clang \
            llvm \
            kernel-devel \
            kernel-headers \
            gcc \
            make \
            libbpf-devel
        ;;
    *)
        echo "⚠️  Unsupported OS: $OS"
        echo "Please install manually:"
        echo "  - clang (>= 10)"
        echo "  - llvm"
        echo "  - kernel headers"
        echo "  - gcc/make"
        exit 1
        ;;
esac

# 验证安装
echo ""
echo "🔍 Verifying installation..."

if command -v clang >/dev/null 2>&1; then
    echo "✅ clang: $(clang --version | head -n1)"
else
    echo "❌ clang not found"
    exit 1
fi

if command -v llvm-config >/dev/null 2>&1; then
    echo "✅ LLVM: $(llvm-config --version)"
else
    echo "⚠️  llvm-config not found"
fi

if [ -d "/lib/modules/$(uname -r)" ]; then
    echo "✅ Kernel modules: $(uname -r)"
else
    echo "❌ Kernel modules not found"
    exit 1
fi

if [ -d "/usr/include/linux" ]; then
    echo "✅ Linux headers: found"
else
    echo "❌ Linux headers not found"
    exit 1
fi

echo ""
echo "🎉 All dependencies installed successfully!"
echo "You can now run: make build-ebpf"
