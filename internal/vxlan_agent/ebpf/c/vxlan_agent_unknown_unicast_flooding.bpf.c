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
    my_bpf_printk("tcx/ingress. %d 1. packet received", skb->ifindex);

    if (skb == NULL)
        return TC_ACT_OK;

    __u64 current_time = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)skb->data;

    if ((void *)(eth + 1) > (void *)(long)skb->data_end)
        return TC_ACT_OK;

    //my_bpf_printk("tcx/ingress %d 2. packet recieved", skb->ifindex);

    __u32 ifindex = skb->ingress_ifindex;
    bool *ifindex_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &ifindex);

    if (ifindex_is_internal == NULL)
    {
        //my_bpf_printk("tcx/ingress %d 3. interface is not registered in ifindex_is_internal_map", skb->ingress_ifindex);
        return TC_ACT_OK;
    }

    bool packet_is_received_by_internal_iface = *ifindex_is_internal;

    int zero = 0; // Key for the first element
    __u32 *number_of_internal_ifindexes = bpf_map_lookup_elem(&internal_ifindexes_array_length, &zero);
    __u32 *number_of_remote_border_ips = bpf_map_lookup_elem(&remote_border_ips_array_length, &zero);

    if (number_of_internal_ifindexes == NULL || number_of_remote_border_ips == NULL || *number_of_internal_ifindexes == 0 || *number_of_remote_border_ips == 0)
    {
        //my_bpf_printk("tcx/ingress %d 4. number_of_internal_ifindexes or number_of_external_ifindexes is NULL or 0", skb->ingress_ifindex);
        return TC_ACT_OK;
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
    //my_bpf_printk("tcx/ingress int_to_ext %d 5. start clone_internal_packet_and_send_to_all_internal_ifaces_and_external_border_ips", skb->ingress_ifindex);
    int i;
    __u32 *ifindex_ptr;

    bpf_for(i, 0, MAX_INTERNAL_IFINDEXES)
    {
        if (i >= number_of_internal_ifindexes)
            break;

        //my_bpf_printk("tcx/ingress int_to_ext %d 6. find internal if index i=%d", skb->ingress_ifindex, i);

        ifindex_ptr = bpf_map_lookup_elem(&internal_ifindexes_array, &i);

        if (ifindex_ptr == NULL)
        {
            //my_bpf_printk("tcx/ingress int_to_ext %d 7. internal_ifindexes_array[%d] is NULL", skb->ingress_ifindex, i);
            return;
        }

        if (*ifindex_ptr != skb->ingress_ifindex)
        {
            //my_bpf_printk("tcx/ingress int_to_ext %d 8. cloning and redirecting packet i=%d to internal interface", skb->ingress_ifindex, i);
            bpf_clone_redirect(skb, *ifindex_ptr, 0);
        }
    }


    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *inner_eth = data;

    // Calculate the new packet length
    int old_len = data_end - data;
    //my_bpf_printk("tcx/ingress. int_to_ext %d 16. old_len=%d", skb->ingress_ifindex, old_len);


    // Resize the packet buffer by increasing the headroom.
    // in bpf_xdp_adjust_head() if we want to increase the packet length, we must use negative number
    // in bpf_skb_adjust_room() if we want to increase the packet length, we must use positive number
    // TODO: check if this is the correct way to increase the packet length
    //my_bpf_printk("tcx/ingress int_to_ext %d 9. cloning and redirecting packet to remote borders", skb->ingress_ifindex);
    long ret = bpf_skb_change_head(skb, NEW_HDR_LEN, 0);
    if (ret)
    {
        //my_bpf_printk("tcx/ingress. int_to_ext %d 10. failed to adjust room for external interface %d error %d", skb->ingress_ifindex, i, ret);
        return;
    } else {
        //my_bpf_printk("tcx/ingress. int_to_ext %d 10. successful adjust room for external interface %d", skb->ingress_ifindex, i);
    }

    int new_len = old_len + NEW_HDR_LEN;
    //my_bpf_printk("tcx/ingress. int_to_ext %d 16. new_len=%d", skb->ingress_ifindex, new_len);

    //my_bpf_printk("tcx/ingress. int_to_ext %d 10. cloning & redirecting to remote borders", skb->ingress_ifindex);

    bpf_for(i, 0, MAX_REMOTE_BORDERS_IPS)
    {

        // ==============================================================================================================

        if (i >= number_of_remote_border_ips)
            break;

        //my_bpf_printk("tcx/ingress. int_to_ext %d 11. try to find remote border ip i=[%d]", skb->ingress_ifindex, i);

        struct in_addr *remote_border_ip = bpf_map_lookup_elem(&remote_border_ips_array, &i);

        if (remote_border_ip == NULL)
        {
            //my_bpf_printk("tcx/ingress. int_to_ext %d 12. unable to find remote border ip i=[%d]", skb->ingress_ifindex, i);
            return;
        }

        //my_bpf_printk("tcx/ingress. int_to_ext %d 13. try to find remote border route_info i=[%d]", skb->ingress_ifindex, i);
        struct external_route_info *route_info = bpf_map_lookup_elem(&border_ip_to_route_info_map, remote_border_ip);

        if (route_info == NULL)
        {
            //my_bpf_printk("tcx/ingress. int_to_ext %d 14. unable to find remote border route_info i=[%d]", skb->ingress_ifindex, i);
            return;
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

        //my_bpf_printk("tcx/ingress. int_to_ext %d 15. setting packet fields before redirecting i=[%d]", skb->ingress_ifindex, i);

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
            //my_bpf_printk("tcx/ingress. int_to_ext %d 16. incorrect data & data_end size after adjusting size i=[%d]", skb->ingress_ifindex, i);
            return;
        }

        outer_eth = data;
        outer_iph = data + ETH_HLEN; // ETH_HLEN == 14 & ETH_ALEN == 6
        outer_udph = data + ETH_HLEN + IP_HDR_LEN;
        outer_vxh = data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN;

        __builtin_memcpy(outer_eth->h_source, route_info->external_iface_mac.addr, ETH_ALEN);        // mac address is a byte sequence, not affected by endianness
        __builtin_memcpy(outer_eth->h_dest, route_info->external_iface_next_hop_mac.addr, ETH_ALEN); // mac address is a byte sequence, not affected by endianness
        outer_eth->h_proto = bpf_htons(ETH_P_IP);                                                    // ip address is a multi-byte value, so it needs to be in network byte order

        outer_iph->version = 4;                                             // ip version
        outer_iph->ihl = 5;                                                 // ip header length
        outer_iph->tos = 0;                                                 // ip type of service
        outer_iph->tot_len = bpf_htons(new_len - ETH_HLEN);                 // ip total length
        //my_bpf_printk("tcx/ingress. int_to_ext %d 16. outer_iph->tot_len=%d", skb->ingress_ifindex, new_len - ETH_HLEN);
        outer_iph->id = 0;                                                  // ip id
        outer_iph->frag_off = 0;                                            // ip fragment offset
        outer_iph->ttl = 64;                                                // ip time to live
        outer_iph->protocol = IPPROTO_UDP;                                  // ip protocol
        outer_iph->check = 0;                                               // ip checksum will be calculated later
        outer_iph->saddr = bpf_htonl(route_info->external_iface_ip.s_addr); // ip source address
        outer_iph->daddr = bpf_htonl(remote_border_ip->s_addr);             // ip destination address

        outer_udph->source = bpf_htons(get_ephemeral_port());         // Source UDP port
        outer_udph->dest = bpf_htons(4790);                           // Destination UDP port (VXLAN default)
        outer_udph->len = bpf_htons(new_len - ETH_HLEN - IP_HDR_LEN); // UDP length
        outer_udph->check = 0;                                        // UDP checksum is optional in IPv4

        // for now we don't set VXLAN header

        // Calculate ip checksum
        //my_bpf_printk("tcx/ingress. int_to_ext %d 16. fixing checksum before redirecting i=[%d]", skb->ingress_ifindex, i);
        outer_iph->check = ~bpf_csum_diff(0, 0, (__u32 *)outer_iph, IP_HDR_LEN, 0);

        //my_bpf_printk("tcx/ingress. int_to_ext %d 16. performing the redirection i=[%d]", skb->ingress_ifindex, i);
        bpf_clone_redirect(skb, route_info->external_iface_index, 0);
    }
}

// --------------------------------------------------------

static void __always_inline clone_external_packet_and_send_to_all_internal_ifaces(struct __sk_buff *skb, __u32 number_of_internal_ifindexes)
{
    //my_bpf_printk("tcx/ingress ext_to_int %d 5. start clone_external_packet_and_send_to_all_internal_ifaces", skb->ingress_ifindex);
    int i;
    __u32 *ifindex_ptr;

    bpf_for(i, 0, MAX_INTERNAL_IFINDEXES)
    {
        if (i >= number_of_internal_ifindexes)
            break;


        //my_bpf_printk("tcx/ingress ext_to_int %d 8. try to lookup internal if index before forwarding the packet to it i=%d", skb->ingress_ifindex, i);
        ifindex_ptr = bpf_map_lookup_elem(&internal_ifindexes_array, &i);

        if (ifindex_ptr == NULL)
        {

            //my_bpf_printk("tcx/ingress ext_to_int %d 8. did not find if index to forward the pcaket to. i=%d", skb->ingress_ifindex, i);
            return;
        }


        //my_bpf_printk("tcx/ingress ext_to_int %d 8. redirecting the packet to if index. i=%d", skb->ingress_ifindex, i);
        bpf_clone_redirect(skb, *ifindex_ptr, 0);
    }
}