# eBPF Objects Directory

This directory contains the compiled eBPF object files that are embedded into the Go binary.

## Files

- `network-monitor.o` - Compiled from `ebpf/network/monitor.c`
- `security-monitor.o` - Compiled from `ebpf/security/monitor.c`

## Building

These files are automatically generated and copied here when you run:

```bash
make build-ebpf
```

The build process:
1. Compiles C source files to `.o` files in `bin/ebpf/`
2. Copies the `.o` files to this directory for embedding
3. Go's `//go:embed` directive includes them in the binary
