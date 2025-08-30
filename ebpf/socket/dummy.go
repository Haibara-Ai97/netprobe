//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../include" --target=amd64 SocketMonitor monitor.c
package socket
