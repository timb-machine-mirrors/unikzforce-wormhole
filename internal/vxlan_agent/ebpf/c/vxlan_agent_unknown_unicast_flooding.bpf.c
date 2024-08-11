#include "../../../../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --------------------------------------------------------

// will use these info in case we want to forward a packet to
// external network
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in_addr);
    __type(value, struct external_route_info);
    __uint(max_entries, 4 * 1024);
} border_ip_to_route_info_map SEC(".maps");

// --------------------------------------------------------

#define MAX_INTERNAL_IFINDEXES 10

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_INTERNAL_IFINDEXES);
} internal_ifindexes_array SEC(".maps");

// --------------------------------------------------------

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} internal_ifindexes_array_length SEC(".maps");

// --------------------------------------------------------

#define MAX_EXTERNAL_IFINDEXES 10

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_EXTERNAL_IFINDEXES);
} external_ifindexes_array SEC(".maps");

// --------------------------------------------------------

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} external_ifindexes_array_length SEC(".maps");

// --------------------------------------------------------

// it will tell us whether a iface index is external or internal
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, bool);
    __uint(max_entries, 4 * 1024);
} ifindex_is_internal_map SEC(".maps");

// --------------------------------------------------------

static void __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb);
static void __always_inline clone_internal_packet_and_send_to_all_internal_and_external_ifaces(struct __sk_buff *skb, __u32 number_of_internal_ifindexes, __u32 number_of_external_ifindexes);
static void __always_inline clone_internal_packet_and_send_to_internal_iface(struct __sk_buff *skb, __u32 ifindex);
static void __always_inline clone_internal_packet_and_send_to_external_iface(struct __sk_buff *skb, __u32 ifindex);
static void __always_inline clone_external_packet_and_send_to_internal_iface(struct __sk_buff *skb, __u32 ifindex);

// --------------------------------------------------------

SEC("tcx/ingress")
int vxlan_agent_unknown_unicast_flooding(struct __sk_buff *skb)
{
    __u64 current_time = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)skb->data;

    if ((void *)(eth + 1) > (void *)(long)skb->data_end)
        return TC_ACT_SHOT;

    bool *ifindex_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &skb->ingress_ifindex);

    if (ifindex_is_internal == NULL)
    {
        bpf_printk("interface is not registered in ifindex_is_internal_map");
        return TC_ACT_SHOT;
    }

    bool packet_is_received_by_internal_iface = *ifindex_is_internal;

    int zero = 0; // Key for the first element
    __u32 *number_of_internal_ifindexes = bpf_map_lookup_elem(&internal_ifindexes_array_length, &zero);
    __u32 *number_of_external_ifindexes = bpf_map_lookup_elem(&external_ifindexes_array_length, &zero);

    if (number_of_internal_ifindexes == NULL || number_of_external_ifindexes == NULL || *number_of_internal_ifindexes == 0 || *number_of_external_ifindexes == 0)
    {
        bpf_printk("number_of_internal_ifindexes or number_of_external_ifindexes is NULL or 0");
        return TC_ACT_SHOT;
    }

    if (packet_is_received_by_internal_iface)
    {
        clone_internal_packet_and_send_to_all_internal_and_external_ifaces(skb, number_of_internal_ifindexes, number_of_external_ifindexes);
    }
    else
    {
        clone_external_packet_and_send_to_all_internal_ifaces(skb);
    }

    return TC_ACT_OK;
}

// --------------------------------------------------------

static void __always_inline clone_internal_packet_and_send_to_all_internal_and_external_ifaces(struct __sk_buff *skb, __u32 number_of_internal_ifindexes, __u32 number_of_external_ifindexes)
{

    int i;
    __u32 *ifindex_ptr;

    bpf_for(i, 0, MAX_INTERNAL_IFINDEXES)
    {
        if (i >= number_of_internal_ifindexes)
            break;

        ifindex_ptr = bpf_map_lookup_elem(&internal_ifindexes_array, &i);

        if (ifindex_ptr == NULL)
        {
            bpf_printk("internal_ifindexes_array[%d] is NULL", i);
            return;
        }

        bpf_clone_redirect(skb, *ifindex_ptr, 0);
    }

    bpf_for(i, 0, MAX_EXTERNAL_IFINDEXES)
    {
        if (i >= number_of_external_ifindexes)
            break;

        ifindex_ptr = bpf_map_lookup_elem(&external_ifindexes_array, &i);

        if (ifindex_ptr == NULL)
        {
            bpf_printk("external_ifindexes_array[%d] is NULL", i);
            return;
        }

        // if packet need to be forwarded to an external interface
        // we must add outer headers to the packet
        // and then forward it to the external interface
        // so the packet will have:
        // - outer ethernet header
        // - outer ip header
        // - outer udp header
        // - outer vxlan header
        // - inner original layer 2 frame

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct ethhdr* inner_eth = data;

        struct ethhdr* outer_eth;
        struct iphdr* outer_iph;
        struct udphdr* outer_udph;
        struct vxlanhdr* outer_vxh;

        // Calculate the new packet length
        int old_len = data_end - data;
        int new_len = old_len + NEW_HDR_LEN;

        // Resize the packet buffer by increasing the headroom.
        // in bpf_xdp_adjust_head() if we want to increase the packet length, we must use negative number
        // in bpf_skb_adjust_room() if we want to increase the packet length, we must use positive number
        // TODO: check if this is the correct way to increase the packet length
        if (bpf_skb_adjust_room(skb, +NEW_HDR_LEN, BPF_ADJ_ROOM_MAC, 0)) {
            bpf_printk("failed to adjust room for external interface %d", i);
            return;
        }
    }
}

static void __always_inline clone_internal_packet_and_send_to_internal_iface(struct __sk_buff *skb, __u32 ifindex)
{
}

static void __always_inline clone_internal_packet_and_send_to_external_iface(struct __sk_buff *skb, __u32 ifindex)
{
}

// --------------------------------------------------------

static void __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb)
{
}

static void __always_inline clone_external_packet_and_send_to_internal_iface(struct __sk_buff *skb, __u32 ifindex)
{
}