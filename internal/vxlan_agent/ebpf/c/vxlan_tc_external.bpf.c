#include "vxlan_common.bpf.h"
#include "../../../../include/vmlinux.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --------------------------------------------------------

// internal networks. a LPM trie data structure
// for example 192.168.1.0/24 --> VNI 0

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct internal_network_vni);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} internal_networks_map SEC(".maps");

// --------------------------------------------------------

#define MAX_INTERNAL_IFINDEXES 10

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_INTERNAL_IFINDEXES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} internal_ifindexes_array SEC(".maps");

// --------------------------------------------------------

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} internal_ifindexes_array_length SEC(".maps");

// --------------------------------------------------------

static int __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb, __u32 number_of_internal_ifindexes);

// --------------------------------------------------------

SEC("tcx/ingress")
int vxlan_tc_external(struct __sk_buff *skb)
{
    my_bpf_printk("tcx/ingress EXTERNAL. %d 1. packet received", skb->ifindex);

    if (skb == NULL)
        return TC_ACT_SHOT;

    __u64 current_time = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)skb->data;

    if ((void *)(eth + 1) > (void *)(long)skb->data_end)
        return TC_ACT_SHOT;

    my_bpf_printk("tcx/ingress EXTERNAL %d 2. packet recieved", skb->ifindex);

    int zero = 0; // Key for the first element
    __u32 *number_of_internal_ifindexes = bpf_map_lookup_elem(&internal_ifindexes_array_length, &zero);

    if (number_of_internal_ifindexes == NULL || *number_of_internal_ifindexes == 0)
    {
        my_bpf_printk("tcx/ingress EXTERNAL %d 4. number_of_internal_ifindexes or number_of_external_ifindexes is NULL or 0", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    return clone_external_packet_and_send_to_all_internal_ifaces(skb, *number_of_internal_ifindexes);
}

// --------------------------------------------------------

static int __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb, __u32 number_of_internal_ifindexes)
{
    my_bpf_printk("tcx/ingress EXTERNAL  %d 5. start clone_external_packet_and_send_to_all_internal_ifaces", skb->ingress_ifindex);
    int i;
    __u32 *ifindex_ptr;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN > data_end)
    {
        my_bpf_printk("tcx/ingress EXTERNAL  %d 7. invalid data & data_end after decreasing packet head size", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    struct ethhdr *inner_eth = data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN;

    // Ensure the inner Ethernet header is valid
    if ((void *)(inner_eth + 1) > data_end)
        return TC_ACT_SHOT;

    __u16 h_proto = bpf_ntohs(inner_eth->h_proto);

    if (h_proto == ETH_P_ARP)
    {

        struct arphdr *inner_arph = (void *)(inner_eth + 1);

        // Ensure the inner ARP header is valid
        if ((void *)(inner_arph + 1) > data_end)
            return TC_ACT_SHOT;

        struct arp_payload *inner_arp_payload = (void *)(inner_arph + 1);

        // Ensure the inner ARP payload is valid
        if ((void *)(inner_arp_payload + 1) > data_end)
            return TC_ACT_SHOT;


        // Check if packet really belongs to internal network

        struct ipv4_lpm_key key = {.prefixlen = 24};
        __builtin_memcpy(key.data, inner_arp_payload->ar_tip, sizeof(key.data));


        // if the packet is not for internal network do TC_ACT_OK here and 
        int *internal_network_vni = bpf_map_lookup_elem(&internal_networks_map, &key);
        if (internal_network_vni == NULL) {
            my_bpf_printk("tcx/ingres does not belong to internal network. pass it up");
            return TC_ACT_OK;
        }

    }
    else if (h_proto == ETH_P_IP)
    {

        struct iphdr *inner_iph = (void *)(inner_eth + 1);

        // Ensure the inner IP header is valid
        if ((void *)(inner_iph + 1) > data_end)
            return TC_ACT_SHOT;

        // Extract inner source and destination IP addresses
        __u32 inner_dst_ip = inner_iph->daddr;

        // Check if packet really belongs to internal network
        struct ipv4_lpm_key key = {.prefixlen = 24};

        __builtin_memcpy(key.data, &inner_dst_ip, sizeof(key.data));


        // if the packet is not for internal network do TC_ACT_OK here and 
        int *internal_network_vni = bpf_map_lookup_elem(&internal_networks_map, &key);
        if (internal_network_vni == NULL) {
            my_bpf_printk("TC does not belong to internal network. pass it up");
            return TC_ACT_OK;
        }

    }
    else
    {
        return TC_ACT_SHOT;
    }

    struct ethhdr *outer_eth = data;

    if ((void *)outer_eth + sizeof(struct ethhdr) > data_end)
    {
        my_bpf_printk("tcx/ingress EXTERNAL  %d 7. invalid outer_eth pointer", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    if ((void *)inner_eth + sizeof(struct ethhdr) > data_end)
    {
        my_bpf_printk("tcx/ingress EXTERNAL  %d 7. invalid outer_eth pointer", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    __builtin_memcpy(outer_eth->h_source, inner_eth->h_source, ETH_ALEN);
    __builtin_memcpy(outer_eth->h_dest, inner_eth->h_dest, ETH_ALEN);
    outer_eth->h_proto = inner_eth->h_proto;

    // Resize the packet buffer by decreasing the headroom.
    // in bpf_xdp_adjust_head() if we want to decrease the packet length, we must use positive number
    // in bpf_skb_adjust_room() if we want to decrease the packet length, we must use negative number
    // TODO: check if this is the correct way to decrease the packet length
    long ret = bpf_skb_adjust_room(skb, -NEW_HDR_LEN, BPF_ADJ_ROOM_MAC, 0);
    if (ret)
    {
        my_bpf_printk("tcx/ingress EXTERNAL  %d 6. failed to decrease the packet head using bpf_skb_change_head(), error = %d", skb->ingress_ifindex, ret);
        return TC_ACT_SHOT;
    }
    else
    {
        my_bpf_printk("tcx/ingress EXTERNAL  %d 6. sucessful decreasing of the packet head using bpf_skb_change_head()", skb->ingress_ifindex);
    }

    // Recalculate data and data_end pointers after adjustment
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // Ensure the packet is still valid after adjustment
    if (data + sizeof(struct ethhdr) > data_end)
    {
        my_bpf_printk("tcx/ingress EXTERNAL  %d 7. invalid data & data_end after decreasing packet head size", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    bpf_for(i, 0, MAX_INTERNAL_IFINDEXES)
    {
        if (i >= number_of_internal_ifindexes)
            break;

        my_bpf_printk("tcx/ingress EXTERNAL  %d 8. try to lookup internal if index before forwarding the packet to it i=%d", skb->ingress_ifindex, i);
        ifindex_ptr = bpf_map_lookup_elem(&internal_ifindexes_array, &i);

        if (ifindex_ptr == NULL)
        {

            my_bpf_printk("tcx/ingress EXTERNAL  %d 8. did not find if index to forward the pcaket to. i=%d", skb->ingress_ifindex, i);
            return TC_ACT_SHOT;
        }

        my_bpf_printk("tcx/ingress EXTERNAL  %d 8. redirecting the packet to if index. i=%d", skb->ingress_ifindex, i);
        bpf_clone_redirect(skb, *ifindex_ptr, 0);
    }

    return TC_ACT_OK;
}