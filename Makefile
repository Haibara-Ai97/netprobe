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
CLANG_FLAGS=-O2 -g -Wall -Werror -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wunused -Wall

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
	@for dir in $(shell find $(EBPF_DIR) -type d -name "*.c" -exec dirname {} \;); do \
		for file in $$dir/*.c; do \
			if [ -f "$$file" ]; then \
				output=$$(echo $$file | sed 's|$(EBPF_DIR)|$(BUILD_DIR)/ebpf|' | sed 's|\.c$$|.o|'); \
				mkdir -p $$(dirname $$output); \
				echo "Compiling $$file -> $$output"; \
				$(CLANG) $(CLANG_FLAGS) -target bpf -c $$file -o $$output; \
			fi \
		done \
	done

# 安装依赖
install-deps:
	@echo "Installing Go dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

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
