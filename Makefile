.PHONY: build clean test build-ebpf install-deps fmt vet lint

# 变量定义
BINARY_NAME=kube-net-probe
VERSION?=v0.1.0
BUILD_DIR=./bin
EBPF_DIR=./ebpf
PKG_DIR=./pkg

# Go 相关变量
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# eBPF 相关变量
CLANG=clang
CLANG_FLAGS=-O2 -g -Wall -Werror \
	-D__KERNEL__ -D__BPF_TRACING__ \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member \
	-I/usr/include \
	-I/usr/include/$(shell uname -m)-linux-gnu

# 构建目标
build: build-ebpf
	@echo "Building KubeNetProbe..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -v -o $(BUILD_DIR)/manager ./cmd/manager
	$(GOBUILD) -v -o $(BUILD_DIR)/agent ./cmd/agent
	$(GOBUILD) -v -o $(BUILD_DIR)/cli ./cmd/cli

# 构建 eBPF 程序
build-ebpf:
	@echo "Building eBPF programs..."
	@mkdir -p $(BUILD_DIR)/ebpf
	@mkdir -p pkg/ebpf/objects
	@echo "Compiling network monitor..."
	$(CLANG) $(CLANG_FLAGS) -target bpf -c $(EBPF_DIR)/network/monitor.c -o $(BUILD_DIR)/ebpf/network-monitor.o
	@echo "Compiling security monitor..."
	$(CLANG) $(CLANG_FLAGS) -target bpf -c $(EBPF_DIR)/security/monitor.c -o $(BUILD_DIR)/ebpf/security-monitor.o
	@echo "Copying objects for embedding..."
	@cp $(BUILD_DIR)/ebpf/network-monitor.o pkg/ebpf/objects/
	@cp $(BUILD_DIR)/ebpf/security-monitor.o pkg/ebpf/objects/ || echo "Warning: security-monitor.o not found, creating placeholder"
	@if [ ! -f pkg/ebpf/objects/security-monitor.o ]; then \
		echo "Creating placeholder security monitor object..."; \
		touch pkg/ebpf/objects/security-monitor.o; \
	fi

# 安装依赖
install-deps:
	@echo "Installing Go dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# 安装系统依赖
install-system-deps:
	@echo "Installing system dependencies..."
	@chmod +x scripts/install_deps.sh
	@./scripts/install_deps.sh

# 生成 bpf2go 代码
generate-bpf:
	@echo "Generating bpf2go code..."
	cd pkg/ebpf && go generate ./...
	@echo "✅ bpf2go code generated"

# 构建 bpf2go 示例
build-bpf2go: generate-bpf
	@echo "Building bpf2go TC monitor example..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -v -o $(BUILD_DIR)/tc_monitor_bpf2go examples/tc_monitor_example.go
	@echo "✅ bpf2go example built"

# 运行 bpf2go 示例
run-bpf2go: build-bpf2go
	@echo "Running bpf2go TC monitor example..."
	@echo "Note: This requires root privileges to attach eBPF programs"
	sudo $(BUILD_DIR)/tc_monitor_bpf2go eth0

# 构建 eBPF 程序（简化版本）
build-ebpf-simple:
	@echo "Building eBPF programs (simple version)..."
	@mkdir -p $(BUILD_DIR)/ebpf
	@mkdir -p pkg/ebpf/objects
	@echo "Compiling network monitor..."
	$(CLANG) $(CLANG_FLAGS) -target bpf -c $(EBPF_DIR)/network/monitor.c -o $(BUILD_DIR)/ebpf/network-monitor.o
	@echo "Copying objects for embedding..."
	@cp $(BUILD_DIR)/ebpf/network-monitor.o pkg/ebpf/objects/
	@touch pkg/ebpf/objects/security-monitor.o

# 构建 eBPF 程序（最简版本，如果其他都失败）
build-ebpf-minimal:
	@echo "Building eBPF programs (minimal version)..."
	@mkdir -p $(BUILD_DIR)/ebpf
	@mkdir -p pkg/ebpf/objects
	@echo "Compiling minimal network monitor..."
	$(CLANG) -O2 -target bpf -c $(EBPF_DIR)/network/monitor_fixed.c -o $(BUILD_DIR)/ebpf/network-monitor.o
	@echo "Copying objects for embedding..."
	@cp $(BUILD_DIR)/ebpf/network-monitor.o pkg/ebpf/objects/
	@touch pkg/ebpf/objects/security-monitor.o

# 运行测试
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# 运行基准测试
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# 代码格式化
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# 代码检查
vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

# 代码 lint
lint:
	@echo "Running golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping lint"; \
	fi

# 清理构建文件
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# 生成 Kubernetes YAML
generate-k8s:
	@echo "Generating Kubernetes manifests..."
	@mkdir -p deploy/generated
	$(GOCMD) run ./tools/generate-manifests

# 构建 Docker 镜像
docker-build:
	@echo "Building Docker images..."
	docker build -t $(BINARY_NAME)-manager:$(VERSION) -f build/manager/Dockerfile .
	docker build -t $(BINARY_NAME)-agent:$(VERSION) -f build/agent/Dockerfile .

# 推送 Docker 镜像
docker-push:
	@echo "Pushing Docker images..."
	docker push $(BINARY_NAME)-manager:$(VERSION)
	docker push $(BINARY_NAME)-agent:$(VERSION)

# 部署到 Kubernetes
deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f deploy/

# 从 Kubernetes 卸载
undeploy:
	@echo "Undeploying from Kubernetes..."
	kubectl delete -f deploy/ --ignore-not-found=true

# 查看日志
logs-manager:
	kubectl logs -l app=kube-net-probe-manager -n kube-net-probe -f

logs-agent:
	kubectl logs -l app=kube-net-probe-agent -n kube-net-probe -f

# 开发环境设置
dev-setup: install-deps
	@echo "Setting up development environment..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.54.2; \
	fi

# 代码生成
generate:
	@echo "Generating code..."
	$(GOCMD) generate ./...

# 完整构建流程
all: clean install-deps fmt vet lint test build

# 帮助信息
help:
	@echo "Available targets:"
	@echo "  build         - Build all binaries"
	@echo "  build-ebpf    - Build eBPF programs"
	@echo "  install-deps  - Install Go dependencies"
	@echo "  test          - Run tests"
	@echo "  bench         - Run benchmarks"
	@echo "  fmt           - Format code"
	@echo "  vet           - Run go vet"
	@echo "  lint          - Run golangci-lint"
	@echo "  clean         - Clean build files"
	@echo "  docker-build  - Build Docker images"
	@echo "  docker-push   - Push Docker images"
	@echo "  deploy        - Deploy to Kubernetes"
	@echo "  undeploy      - Remove from Kubernetes"
	@echo "  dev-setup     - Setup development environment"
	@echo "  all           - Run complete build pipeline"
	@echo "  help          - Show this help message"
