package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include" -type new_discovered_entry VxlanAgentXDP ./c/vxlan_agent_xdp.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I../../../include" -type new_discovered_entry VxlanAgentUnknownUnicastFlooding ./c/vxlan_agent_unknown_unicast_flooding.bpf.c
