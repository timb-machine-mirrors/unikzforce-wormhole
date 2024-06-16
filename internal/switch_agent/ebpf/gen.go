package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type mac_address_iface_entry SwitchAgentXDP ./c/switch_agent_xdp.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go SwitchAgentUnknownUnicastFlooding ./c/switch_agent_unknown_unicast_flooding.bpf.c
