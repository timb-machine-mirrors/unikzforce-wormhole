#include "vxlan_agent.bpf.h"
#include "../../../../include/vmlinux.h"

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

#define MAX_REMOTE_BORDERS_IPS 10

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_REMOTE_BORDERS_IPS);
} remote_border_ips_array SEC(".maps");

// --------------------------------------------------------

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct in_addr);
    __uint(max_entries, 1);
} remote_border_ips_array_length SEC(".maps");

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

static void __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb, __u32 number_of_internal_ifindexes);
static void __always_inline clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips(struct __sk_buff *skb, __u32 number_of_internal_ifindexes, __u32 number_of_external_ifindexes);

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
    __u32 *number_of_remote_border_ips = bpf_map_lookup_elem(&remote_border_ips_array_length, &zero);

    if (number_of_internal_ifindexes == NULL || number_of_remote_border_ips == NULL || *number_of_internal_ifindexes == 0 || *number_of_remote_border_ips == 0)
    {
        bpf_printk("number_of_internal_ifindexes or number_of_external_ifindexes is NULL or 0");
        return TC_ACT_SHOT;
    }

    if (packet_is_received_by_internal_iface)
    {
        clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips(skb, *number_of_internal_ifindexes, *number_of_remote_border_ips);
    }
    else
    {
        clone_external_packet_and_send_to_all_internal_ifaces(skb, *number_of_internal_ifindexes);
    }

    return TC_ACT_OK;
}

// --------------------------------------------------------

static void __always_inline clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips(struct __sk_buff *skb, __u32 number_of_internal_ifindexes, __u32 number_of_remote_border_ips)
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

        if (*ifindex_ptr != skb->ingress_ifindex)
        {
            bpf_clone_redirect(skb, *ifindex_ptr, 0);
        }
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
    struct ethhdr *inner_eth = data;

    struct ethhdr *outer_eth;
    struct iphdr *outer_iph;
    struct udphdr *outer_udph;
    struct vxlanhdr *outer_vxh;

    // Calculate the new packet length
    int old_len = data_end - data;
    int new_len = old_len + NEW_HDR_LEN;

    // Resize the packet buffer by increasing the headroom.
    // in bpf_xdp_adjust_head() if we want to increase the packet length, we must use negative number
    // in bpf_skb_adjust_room() if we want to increase the packet length, we must use positive number
    // TODO: check if this is the correct way to increase the packet length
    if (bpf_skb_adjust_room(skb, +NEW_HDR_LEN, BPF_ADJ_ROOM_MAC, 0))
    {
        bpf_printk("failed to adjust room for external interface %d", i);
        return;
    }

    // Recalculate data and data_end pointers after adjustment
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // Ensure the packet is still valid after adjustment
    if (data + new_len > data_end)
    {
        bpf_printk("packet is not valid after size adjustment");
        return;
    }

    outer_eth = data;
    outer_iph = data + ETH_HLEN; // ETH_HLEN == 14 & ETH_ALEN == 6
    outer_udph = (void *)outer_iph + IP_HDR_LEN;
    outer_vxh = (void *)outer_udph + UDP_HDR_LEN;

    bpf_for(i, 0, MAX_REMOTE_BORDERS_IPS)
    {
        if (i >= number_of_remote_border_ips)
            break;

        struct in_addr *remote_border_ip = bpf_map_lookup_elem(&remote_border_ips_array, &i);

        if (remote_border_ip == NULL)
        {
            bpf_printk("remote_border_ip[%d] is NULL", i);
            return;
        }

        struct external_route_info *route_info = bpf_map_lookup_elem(&border_ip_to_route_info_map, remote_border_ip);

        if (route_info == NULL)
        {
            bpf_printk("route_info for remote_border_ip %s is NULL", remote_border_ip);
            return;
        }

        __builtin_memcpy(outer_eth->h_source, route_info->external_iface_mac.addr, ETH_ALEN);        // mac address is a byte sequence, not affected by endianness
        __builtin_memcpy(outer_eth->h_dest, route_info->external_iface_next_hop_mac.addr, ETH_ALEN); // mac address is a byte sequence, not affected by endianness
        outer_eth->h_proto = bpf_htons(ETH_P_IP);                                                    // ip address is a multi-byte value, so it needs to be in network byte order

        outer_iph->version = 4;                                      // ip version
        outer_iph->ihl = 5;                                          // ip header length
        outer_iph->tos = 0;                                          // ip type of service
        outer_iph->tot_len = bpf_htons(new_len - ETH_HLEN);          // ip total length
        outer_iph->id = 0;                                           // ip id
        outer_iph->frag_off = 0;                                     // ip fragment offset
        outer_iph->ttl = 64;                                         // ip time to live
        outer_iph->protocol = IPPROTO_UDP;                           // ip protocol
        outer_iph->check = 0;                                        // ip checksum will be calculated later
        outer_iph->saddr = bpf_htonl(route_info->external_iface_ip.s_addr); // ip source address
        outer_iph->daddr = bpf_htonl(remote_border_ip->s_addr);             // ip destination address

        outer_udph->source = bpf_htons(get_ephemeral_port());         // Source UDP port
        outer_udph->dest = bpf_htons(4789);                           // Destination UDP port (VXLAN default)
        outer_udph->len = bpf_htons(new_len - ETH_HLEN - IP_HDR_LEN); // UDP length
        outer_udph->check = 0;                                        // UDP checksum is optional in IPv4

        // for now we don't set VXLAN header

        // Calculate ip checksum
        outer_iph->check = ~bpf_csum_diff(0, 0, (__u32 *)outer_iph, IP_HDR_LEN, 0);

        bpf_clone_redirect(skb, *ifindex_ptr, 0);
    }
}

// --------------------------------------------------------

static void __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb, __u32 number_of_internal_ifindexes)
{
    int i;
    __u32 *ifindex_ptr;

    // Resize the packet buffer by decreasing the headroom.
    // in bpf_xdp_adjust_head() if we want to decrease the packet length, we must use positive number
    // in bpf_skb_adjust_room() if we want to decrease the packet length, we must use negative number
    // TODO: check if this is the correct way to decrease the packet length
    if (bpf_skb_adjust_room(skb, -NEW_HDR_LEN, BPF_ADJ_ROOM_MAC, 0))
    {
        bpf_printk("failed to adjust room for external interface %d", i);
        return;
    }

    // Recalculate data and data_end pointers after adjustment
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ensure the packet is still valid after adjustment
    if (data + sizeof(struct ethhdr) > data_end)
    {
        bpf_printk("packet is not valid after size adjustment");
        return;
    }

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
}