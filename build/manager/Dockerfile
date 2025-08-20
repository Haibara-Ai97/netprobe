FROM golang:1.21-alpine AS builder

WORKDIR /workspace

# 安装构建依赖
RUN apk add --no-cache gcc musl-dev linux-headers

# 复制 go mod 文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY cmd/ cmd/
COPY pkg/ pkg/

# 构建二进制文件
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o manager ./cmd/manager

# 最终镜像
FROM alpine:3.18

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# 复制二进制文件
COPY --from=builder /workspace/manager .

# 复制 eBPF 程序
COPY bin/ebpf/ /etc/ebpf/

USER 65534:65534

ENTRYPOINT ["./manager"]
