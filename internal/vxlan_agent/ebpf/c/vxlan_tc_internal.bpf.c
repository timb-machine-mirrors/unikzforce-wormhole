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

// will use these info in case we want to forward a packet to
// external network
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in_addr);
    __type(value, struct external_route_info);
    __uint(max_entries, 4 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} border_ip_to_route_info_map SEC(".maps");

// --------------------------------------------------------

static int __always_inline clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips(struct __sk_buff *skb, struct ethhdr *eth);

// --------------------------------------------------------

SEC("tcx/ingress")
int vxlan_tc_internal(struct __sk_buff *skb)
{
    my_bpf_printk("tcx/ingress INTERNAL. %d 1. packet received", skb->ifindex);

    if (skb == NULL)
        return TC_ACT_SHOT;

    __u64 current_time = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)skb->data;

    if ((void *)(eth + 1) > (void *)(long)skb->data_end)
        return TC_ACT_SHOT;

    my_bpf_printk("tcx/ingress INTERNAL %d 2. packet recieved", skb->ifindex);

    return clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips(skb, eth);
}

// --------------------------------------------------------

static int __always_inline clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips(struct __sk_buff *skb, struct ethhdr *eth)
{
    my_bpf_printk("tcx/ingress INTERNAL  %d 5. start clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips", skb->ingress_ifindex);
    int i;

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    struct ipv4_lpm_key key = {.prefixlen = 32};

    if (h_proto == ETH_P_ARP)
    {
        struct arphdr *arph = (void *)(eth + 1);

        if ((void *)(arph + 1) > (void *)(long)skb->data_end)
            return TC_ACT_SHOT;

        struct arp_payload *arp_payload = (void *)(arph + 1);

        if ((void *)(arp_payload + 1) > (void *)(long)skb->data_end)
            return TC_ACT_SHOT;

        __builtin_memcpy(key.data, arp_payload->ar_tip, sizeof(key.data));

        my_bpf_printk("Target IP: %d.%d.%d.%d\n",
            key.data[0],
            key.data[1],
            key.data[2],
            key.data[3]);
    }
    else if (h_proto == ETH_P_IP)
    {

        struct iphdr *iph = (void *)(eth + 1);

        // Ensure the inner IP header is valid
        if ((void *)(iph + 1) > (void *)(long)skb->data_end)
            return TC_ACT_SHOT;

        // Extract inner source and destination IP addresses
        __u32 dst_ip = iph->daddr;

        __builtin_memcpy(key.data, &dst_ip, sizeof(key.data));
    }
    else
    {
        return TC_ACT_SHOT;
    }

    struct network_vni *dst_network_vni = bpf_map_lookup_elem(&networks_map, &key);
    if (dst_network_vni == NULL)
    {
        my_bpf_printk("tcx/ingres INTERNAL does not belong to internal network. pass it up");
        return TC_ACT_OK;
    }

    if (dst_network_vni->internal_ifindexes == NULL || dst_network_vni->internal_ifindexes_size == NULL || dst_network_vni->border_ips == NULL || dst_network_vni->border_ips_size == NULL)
    {
        my_bpf_printk("tcx/ingres INTERNAL invalid dst_network_vni");
        return TC_ACT_SHOT;
    }

    bpf_for(i, 0, MAX_INTERNAL_IFINDEXES)
    {
        if (i >= dst_network_vni->internal_ifindexes_size)
            break;

        if (dst_network_vni->internal_ifindexes[i] != skb->ingress_ifindex)
        {
            my_bpf_printk("tcx/ingress INTERNAL  %d 8. cloning and redirecting packet i=%d to internal interface", skb->ingress_ifindex, i);
            bpf_clone_redirect(skb, dst_network_vni->internal_ifindexes[i], 0);
        }
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *inner_eth = data;

    // Calculate the new packet length
    int old_len = data_end - data;
    my_bpf_printk("tcx/ingress INTERNAL.  %d 16. old_len=%d", skb->ingress_ifindex, old_len);

    // Resize the packet buffer by increasing the headroom.
    // in bpf_xdp_adjust_head() if we want to increase the packet length, we must use negative number
    // in bpf_skb_adjust_room() if we want to increase the packet length, we must use positive number
    // TODO: check if this is the correct way to increase the packet length
    my_bpf_printk("tcx/ingress INTERNAL  %d 9. cloning and redirecting packet to remote borders", skb->ingress_ifindex);
    long ret = bpf_skb_change_head(skb, NEW_HDR_LEN, 0);
    if (ret)
    {
        my_bpf_printk("tcx/ingress INTERNAL.  %d 10. failed to adjust room for external interface %d error %d", skb->ingress_ifindex, i, ret);
        return TC_ACT_SHOT;
    }
    else
    {
        my_bpf_printk("tcx/ingress INTERNAL.  %d 10. successful adjust room for external interface %d", skb->ingress_ifindex, i);
    }

    int new_len = old_len + NEW_HDR_LEN;
    my_bpf_printk("tcx/ingress INTERNAL.  %d 16. new_len=%d", skb->ingress_ifindex, new_len);

    my_bpf_printk("tcx/ingress INTERNAL.  %d 10. cloning & redirecting to remote borders", skb->ingress_ifindex);

    bpf_for(i, 0, MAX_BORDER_IPS)
    {

        // ==============================================================================================================

        if (i >= dst_network_vni->border_ips_size)
            break;

        struct in_addr *border_ip = &dst_network_vni->border_ips[i];

        my_bpf_printk("tcx/ingress INTERNAL.  %d 13. try to find remote border route_info i=[%d]", skb->ingress_ifindex, i);
        struct external_route_info *route_info = bpf_map_lookup_elem(&border_ip_to_route_info_map, border_ip);

        if (route_info == NULL)
        {
            my_bpf_printk("tcx/ingress INTERNAL.  %d 14. unable to find remote border route_info i=[%d]", skb->ingress_ifindex, i);
            return TC_ACT_SHOT;
        }

        // ==============================================================================================================

        // if packet need to be forwarded to an external interface
        // we must add outer headers to the packet
        // and then forward it to the external interface
        // so the packet will have:
        // - outer ethernet header
        // - outer ip header
        // - outer udp header
        // - outer vxlan header
        // - inner original layer 2 frame

        my_bpf_printk("tcx/ingress INTERNAL.  %d 15. setting packet fields before redirecting i=[%d]", skb->ingress_ifindex, i);

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct ethhdr *inner_eth = data;

        struct ethhdr *outer_eth;
        struct iphdr *outer_iph;
        struct udphdr *outer_udph;
        struct vxlanhdr *outer_vxh;

        // Ensure the packet is still valid after adjustment
        if (data + NEW_HDR_LEN > data_end)
        {
            my_bpf_printk("tcx/ingress INTERNAL.  %d 16. incorrect data & data_end size after adjusting size i=[%d]", skb->ingress_ifindex, i);
            return TC_ACT_SHOT;
        }

        outer_eth = data;
        outer_iph = data + ETH_HLEN; // ETH_HLEN == 14 & ETH_ALEN == 6
        outer_udph = data + ETH_HLEN + IP_HDR_LEN;
        outer_vxh = data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN;

        __builtin_memcpy(outer_eth->h_source, route_info->external_iface_mac.addr, ETH_ALEN);        // mac address is a byte sequence, not affected by endianness
        __builtin_memcpy(outer_eth->h_dest, route_info->external_iface_next_hop_mac.addr, ETH_ALEN); // mac address is a byte sequence, not affected by endianness
        outer_eth->h_proto = bpf_htons(ETH_P_IP);                                                    // ip address is a multi-byte value, so it needs to be in network byte order

        outer_iph->version = 4;                             // ip version
        outer_iph->ihl = 5;                                 // ip header length
        outer_iph->tos = 0;                                 // ip type of service
        outer_iph->tot_len = bpf_htons(new_len - ETH_HLEN); // ip total length
        my_bpf_printk("tcx/ingress INTERNAL.  %d 16. outer_iph->tot_len=%d", skb->ingress_ifindex, new_len - ETH_HLEN);
        outer_iph->id = 0;                                                  // ip id
        outer_iph->frag_off = 0;                                            // ip fragment offset
        outer_iph->ttl = 64;                                                // ip time to live
        outer_iph->protocol = IPPROTO_UDP;                                  // ip protocol
        outer_iph->check = 0;                                               // ip checksum will be calculated later
        outer_iph->saddr = bpf_htonl(route_info->external_iface_ip.s_addr); // ip source address
        outer_iph->daddr = bpf_htonl(border_ip->s_addr);                    // ip destination address

        outer_udph->source = bpf_htons(get_ephemeral_port());         // Source UDP port
        outer_udph->dest = bpf_htons(4790);                           // Destination UDP port (VXLAN default)
        outer_udph->len = bpf_htons(new_len - ETH_HLEN - IP_HDR_LEN); // UDP length
        outer_udph->check = 0;                                        // UDP checksum is optional in IPv4

        // for now we don't set VXLAN header

        // Calculate ip checksum
        my_bpf_printk("tcx/ingress INTERNAL.  %d 16. fixing checksum before redirecting i=[%d]", skb->ingress_ifindex, i);
        outer_iph->check = ~bpf_csum_diff(0, 0, (__u32 *)outer_iph, IP_HDR_LEN, 0);

        my_bpf_printk("tcx/ingress INTERNAL.  %d 16. performing the redirection i=[%d]", skb->ingress_ifindex, i);
        bpf_clone_redirect(skb, route_info->external_iface_index, 0);
    }

    return TC_ACT_OK;
}

// --------------------------------------------------------