#include "../../../../include/vmlinux.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


// --------------------------------------------------------
// main xdp entry point

SEC("xdp.frags")
long dummy_xdp(struct xdp_md *ctx)
{
    return XDP_PASS;
}