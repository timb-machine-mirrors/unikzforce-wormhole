package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" VxlanCommon ./c/vxlan_common.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" VxlanXDPExternal ./c/vxlan_xdp_external.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" VxlanXDPInternal ./c/vxlan_xdp_internal.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" VxlanTCExternal ./c/vxlan_tc_external.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" VxlanTCInternal ./c/vxlan_tc_internal.bpf.c
