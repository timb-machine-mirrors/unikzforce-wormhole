package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" DummyXdp ./c/dummy_xdp.bpf.c
