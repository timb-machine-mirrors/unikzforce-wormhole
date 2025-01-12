#include "vxlan_common.bpf.h"
#include "../../../../include/vmlinux.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --------------------------------------------------------

// a LPM trie data structure
// for example 192.168.1.0/24 --> VNI 0

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct network_vni);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} networks_map SEC(".maps");

// --------------------------------------------------------

static int __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb);

// --------------------------------------------------------

SEC("tcx/ingress")
int vxlan_tc_external(struct __sk_buff *skb)
{
    my_bpf_printk("%d 1. packet received", skb->ifindex);

    if (skb == NULL)
        return TC_ACT_SHOT;

    __u64 current_time = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)skb->data;

    if ((void *)(eth + 1) > (void *)(long)skb->data_end)
        return TC_ACT_SHOT;

    my_bpf_printk("%d 2. packet recieved", skb->ifindex);

    return clone_external_packet_and_send_to_all_internal_ifaces(skb);
}

// --------------------------------------------------------

static int __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb)
{
    my_bpf_printk("%d 5. start clone_external_packet_and_send_to_all_internal_ifaces", skb->ingress_ifindex);
    int i;
    __u32 *ifindex_ptr;
    struct ipv4_lpm_key dst_key = {.prefixlen = 32};
    struct ipv4_lpm_key src_key = {.prefixlen = 32};
    struct in_addr src_ip;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN > data_end)
    {
        my_bpf_printk("%d 7. invalid data & data_end after decreasing packet head size", skb->ingress_ifindex);
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

        create_in_addr_from_arp_ip(inner_arp_payload->ar_sip, &src_ip);
        my_bpf_printk("src_ip obtained by ARP. %u", src_ip.s_addr);

        __builtin_memcpy(dst_key.data, inner_arp_payload->ar_tip, sizeof(dst_key.data));
    }
    else if (h_proto == ETH_P_IP)
    {
        struct iphdr *inner_iph = (void *)(inner_eth + 1);

        // Ensure the inner IP header is valid
        if ((void *)(inner_iph + 1) > data_end)
            return TC_ACT_SHOT;

        // Extract inner source and destination IP addresses
        __u32 inner_dst_ip = inner_iph->daddr;

        src_ip.s_addr = inner_iph->saddr;
        my_bpf_printk("src_ip obtained by IP. %u", src_ip.s_addr);

        // Check if packet really belongs to internal network
        __builtin_memcpy(dst_key.data, &inner_dst_ip, sizeof(dst_key.data));
    }
    else
    {
        return TC_ACT_SHOT;
    }

    // if the packet is not for internal network do TC_ACT_OK here and
    struct network_vni *dst_network_vni = bpf_map_lookup_elem(&networks_map, &dst_key);
    if (dst_network_vni == NULL)
    {
        my_bpf_printk("does not belong to internal network. pass it up");
        return TC_ACT_OK;
    }

    if (!is_ip_in_network(&(dst_network_vni->network), &src_ip))
    {
        my_bpf_printk("src & dst does not belong to same network. pass it up. dst_network_vni %u.%u.%u.%u/%u",
                      dst_network_vni->network.data[0],
                      dst_network_vni->network.data[1],
                      dst_network_vni->network.data[2],
                      dst_network_vni->network.data[3],
                      dst_network_vni->network.prefixlen);

        unsigned char bytes[4];
        bytes[0] = src_ip.s_addr & 0xFF;             // Lowest byte
        bytes[1] = (src_ip.s_addr >> 8) & 0xFF;      // Second byte
        bytes[2] = (src_ip.s_addr >> 16) & 0xFF;     // Third byte
        bytes[3] = (src_ip.s_addr >> 24) & 0xFF;     // Highest byte

        my_bpf_printk("src & dst does not belong to same network. pass it up. src %u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
        return AGENT_PASS;
    };

    struct ethhdr *outer_eth = data;

    if ((void *)outer_eth + sizeof(struct ethhdr) > data_end)
    {
        my_bpf_printk("%d 7. invalid outer_eth pointer", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    if ((void *)inner_eth + sizeof(struct ethhdr) > data_end)
    {
        my_bpf_printk("%d 7. invalid outer_eth pointer", skb->ingress_ifindex);
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
        my_bpf_printk("%d 6. failed to decrease the packet head using bpf_skb_change_head(), error = %d", skb->ingress_ifindex, ret);
        return TC_ACT_SHOT;
    }
    else
    {
        my_bpf_printk("%d 6. sucessful decreasing of the packet head using bpf_skb_change_head()", skb->ingress_ifindex);
    }

    // Recalculate data and data_end pointers after adjustment
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // Ensure the packet is still valid after adjustment
    if (data + sizeof(struct ethhdr) > data_end)
    {
        my_bpf_printk("%d 7. invalid data & data_end after decreasing packet head size", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    bpf_for(i, 0, MAX_INTERNAL_IFINDEXES)
    {
        if (i >= dst_network_vni->internal_ifindexes_size)
            break;

        my_bpf_printk("%d 8. redirecting the packet to if index. i=%d", skb->ingress_ifindex, i);
        bpf_clone_redirect(skb, dst_network_vni->internal_ifindexes[i], 0);
    }

    return TC_ACT_OK;
}