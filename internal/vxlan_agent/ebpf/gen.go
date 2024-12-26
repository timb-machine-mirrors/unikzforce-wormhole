package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" --output-dir ./gen VxlanCommon ./c/vxlan_common.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" --output-dir ./gen VxlanXDPExternal ./c/vxlan_xdp_external.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" --output-dir ./gen VxlanXDPInternal ./c/vxlan_xdp_internal.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" --output-dir ./gen VxlanTCExternal ./c/vxlan_tc_external.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include/vmlinux.h" --output-dir ./gen VxlanTCInternal ./c/vxlan_tc_internal.bpf.c
