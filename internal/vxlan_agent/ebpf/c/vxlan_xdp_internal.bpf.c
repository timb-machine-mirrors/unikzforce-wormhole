#include "vxlan_common.bpf.h"

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
} internal_networks_map SEC(".maps");

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

// it will tell us whether a iface index is external or internal
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, bool);
    __uint(max_entries, 4 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_is_internal_map SEC(".maps");

// --------------------------------------------------------

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mac_address);
    __type(value, struct mac_table_entry);
    __uint(max_entries, 4 * 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mac_table SEC(".maps");

// --------------------------------------------------------

static long __always_inline handle_packet_received_by_internal_iface(struct xdp_md *ctx, __u64 current_time_ns, struct ethhdr *eth);
static enum vxlan_agent_processing_error __always_inline add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(struct xdp_md *ctx, struct mac_address *dst_mac, struct mac_table_entry *dst_mac_entry);
static void __always_inline learn_from_packet_received_by_internal_iface(const struct xdp_md *ctx, __u64 current_time_ns, struct mac_address *src_mac);

// --------------------------------------------------------
// main xdp entry point

SEC("xdp")
long vxlan_xdp_internal(struct xdp_md *ctx)
{
    // we can use current_time_ns as something like a unique identifier for packet
    my_bpf_printk("XDP. %d 1. packet received", ctx->ingress_ifindex);
    __u64 current_time_ns = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)ctx->data;

    // check if the packet is valid
    if ((void *)(eth + 1) > (void *)(long)ctx->data_end)
        return XDP_DROP;

    my_bpf_printk("XDP. %d 2. interface lookup done", ctx->ingress_ifindex);

    return handle_packet_received_by_internal_iface(ctx, current_time_ns, eth);
}

// --------------------------------------------------------

static long __always_inline handle_packet_received_by_internal_iface(struct xdp_md *ctx, __u64 current_time_ns, struct ethhdr *eth)
{
    my_bpf_printk("XDP. %d 3. handle packet received by internal iface", ctx->ingress_ifindex);
    // if packet has been received by an internal iface
    // it means this packet should have no outer headers.
    // we should:
    // - either forward it internally
    // - or add outer headers and forward it to an external interface

    struct mac_address src_mac;
    __builtin_memcpy(src_mac.addr, eth->h_source, ETH_ALEN);

    learn_from_packet_received_by_internal_iface(ctx, current_time_ns, &src_mac);

    my_bpf_printk("XDP. %d 4. learning from packet received by internal internal iface ", ctx->ingress_ifindex);

    struct mac_address dst_mac;
    __builtin_memcpy(dst_mac.addr, eth->h_dest, ETH_ALEN);

    struct mac_table_entry *dst_mac_entry = bpf_map_lookup_elem(&mac_table, &dst_mac);

    my_bpf_printk("XDP. %d 5. searching for dest mac of packet recieved by internal iface ", ctx->ingress_ifindex);

    if (dst_mac_entry != NULL)
    {
        // if we already know this dst mac in mac_table

        my_bpf_printk("XDP. %d 6. found entry for dest mac of packet recieved by internal iface. check if next hop interface is internal or external", ctx->ingress_ifindex);

        __u32 dst_mac_entry_ifindex = dst_mac_entry->ifindex;
        bool *ifindex_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &dst_mac_entry_ifindex);

        if (ifindex_to_redirect_is_internal == NULL)
        {
            my_bpf_printk("XDP. %d 7. next hop not found. ABORT", ctx->ingress_ifindex);
            return XDP_ABORTED;
        }

        bool packet_to_be_redirected_to_an_internal_interface = *ifindex_to_redirect_is_internal;

        if (packet_to_be_redirected_to_an_internal_interface)
        {
            my_bpf_printk("XDP. %d 8. next hop is internal. REDIRECT", ctx->ingress_ifindex);
            // if packet need to be forwarded to an internal interface
            return bpf_redirect(dst_mac_entry->ifindex, 0);
        }
        else
        {

            my_bpf_printk("XDP. %d 8. next hop is external. Add header", ctx->ingress_ifindex);
            // if packet need to be forwarded to an external interface
            enum vxlan_agent_processing_error error = add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(ctx, &dst_mac, dst_mac_entry);

            if (error == AGENT_ERROR_ABORT)
                return XDP_ABORTED;
            else if (error == AGENT_ERROR_DROP)
                return XDP_DROP;

            my_bpf_printk("XDP. %d 9. adding header successful. REDIRECT", ctx->ingress_ifindex);

            return bpf_redirect(dst_mac_entry->ifindex, 0);
        }
    }
    else
    {
        my_bpf_printk("XDP. %d 6. no information found for dest mac of packet received by internal iface. send UP to unknown unicast flooding TC", ctx->ingress_ifindex);

        // if we don't know this dst mac in mac_table
        // no matter why we are here:
        // - either because of a dst mac addr that we don't know where to find (unknown dst mac)
        // - or because dst mac is broadcast mac address ( FFFFFFFFFFFF )
        // in ether case we must perform Flooding --> XDP_PASS --> handle in implemented TC flooding hook

        return XDP_PASS;
    }
}

static enum vxlan_agent_processing_error __always_inline add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(struct xdp_md *ctx, struct mac_address *dst_mac, struct mac_table_entry *dst_mac_entry)
{
    // if packet need to be forwarded to an external interface
    // we must add outer headers to the packet
    // and then forward it to the external interface
    // so the packet will have:
    // - outer ethernet header
    // - outer ip header
    // - outer udp header
    // - outer vxlan header
    // - inner original layer 2 frame

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;

    struct ethhdr *outer_eth;
    struct iphdr *outer_iph;
    struct udphdr *outer_udph;
    struct vxlanhdr *outer_vxh;

    // Calculate the new packet length
    int old_len = data_end - data;
    int new_len = old_len + NEW_HDR_LEN;

    // Resize the packet buffer by increasing the headroom.
    // in packet memory model, the start of the packet which is the ethernet header,
    // has smaller address in memory, and the more we proceed into the deeper packet headers, the bigger the address gets.
    // so when adjusting the packet headroom with -NEW_HDR_LEN, we are actually increasing the size of the packet.
    if (bpf_xdp_adjust_head(ctx, -NEW_HDR_LEN))
        return AGENT_ERROR_ABORT;

    // Recalculate data and data_end pointers after adjustment
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // Ensure the packet is still valid after adjustment
    if (data + sizeof(struct ethhdr) > data_end)
        return AGENT_ERROR_DROP;

    outer_eth = data;
    outer_iph = data + ETH_HLEN; // ETH_HLEN == 14 & ETH_ALEN == 6
    outer_udph = data + ETH_HLEN + IP_HDR_LEN;
    outer_vxh = data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN;

    // Ensure the packet is still valid after adjustment
    if ((void *)(outer_vxh + 1) > data_end)
        return AGENT_ERROR_DROP;

    struct in_addr *dst_border_ip = &(dst_mac_entry->border_ip);

    struct external_route_info *route_info = bpf_map_lookup_elem(&border_ip_to_route_info_map, dst_border_ip);

    if (route_info == NULL)
    {
        // we must have prepopulated route_info in border_ip_to_route_info_map before starting the xdp program.
        // if we don't have it, it means that something is fishy, and we must abort the packet.

        // TODO: function is void, improve error handling later
        return AGENT_ERROR_ABORT;
    }

    //  In network programming, the distinction between the endianness of multi-byte values and byte sequences is critical.
    //  - Multi-byte Values: The endianness affects how multi-byte values (such as 16-bit, 32-bit, and 64-bit integers) are stored
    //    in memory. Network protocols typically require these values to be in big-endian (network byte order) format.
    //    Multi-byte values needs to be handled by bpf_htons() or bpf_htonl(). Like IP addresses, which is a single 32-bit value.
    //  - Byte Sequences: sequences of bytes (such as MAC addresses) are not affected by endianness.
    //    They are simply copied as they are, byte by byte. Like mac addresses, which is a 6 bytes sequence.
    __builtin_memcpy(outer_eth->h_source, route_info->external_iface_mac.addr, ETH_ALEN);        // mac address is a byte sequence, not affected by endianness
    __builtin_memcpy(outer_eth->h_dest, route_info->external_iface_next_hop_mac.addr, ETH_ALEN); // mac address is a byte sequence, not affected by endianness
    outer_eth->h_proto = bpf_htons(ETH_P_IP);                                                    // ip address is a multi-byte value, so it needs to be in network byte order

    outer_iph->version = 4;                                             // ip version
    outer_iph->ihl = 5;                                                 // ip header length
    outer_iph->tos = 0;                                                 // ip type of service
    outer_iph->tot_len = bpf_htons(new_len - ETH_HLEN);                 // ip total length
    outer_iph->id = 0;                                                  // ip id
    outer_iph->frag_off = 0;                                            // ip fragment offset
    outer_iph->ttl = 64;                                                // ip time to live
    outer_iph->protocol = IPPROTO_UDP;                                  // ip protocol
    outer_iph->check = 0;                                               // ip checksum will be calculated later
    outer_iph->saddr = bpf_htonl(route_info->external_iface_ip.s_addr); // ip source address
    outer_iph->daddr = bpf_htonl(dst_border_ip->s_addr);                // ip destination address

    outer_udph->source = bpf_htons(get_ephemeral_port());         // Source UDP port
    outer_udph->dest = bpf_htons(4790);                           // Destination UDP port (VXLAN default)
    outer_udph->len = bpf_htons(new_len - ETH_HLEN - IP_HDR_LEN); // UDP length
    outer_udph->check = 0;                                        // UDP checksum is optional in IPv4

    // for now we don't set VXLAN header

    // Calculate ip checksum
    outer_iph->check = ~bpf_csum_diff(0, 0, (__u32 *)outer_iph, IP_HDR_LEN, 0);

    return AGENT_NO_ERROR;
}

static void __always_inline learn_from_packet_received_by_internal_iface(const struct xdp_md *ctx, __u64 current_time_ns, struct mac_address *src_mac)
{
    struct mac_table_entry *src_mac_entry = bpf_map_lookup_elem(&mac_table, src_mac);

    if (src_mac_entry != NULL)
    {
        bpf_timer_cancel(&src_mac_entry->expiration_timer);
    }

    // if the source mac address is not in the mac table, we need to insert it
    src_mac_entry = &(struct mac_table_entry){
        .last_seen_timestamp_ns = current_time_ns,
        .ifindex = ctx->ingress_ifindex,
        .border_ip = {0}, // in this case, border_ip is set to 0.0.0.0 but it doesn't mean it's really 0.0.0.0 but it means it's not set yet.
        .expiration_timer = {}};

    bpf_map_update_elem(&mac_table, src_mac, src_mac_entry, BPF_ANY);

    src_mac_entry = bpf_map_lookup_elem(&mac_table, src_mac);
    if (!src_mac_entry)
    {
        my_bpf_printk("failed to lookup mac table after update\n");
        return;
    }

    int ret;
    ret = bpf_timer_init(&src_mac_entry->expiration_timer, &mac_table, CLOCK_BOOTTIME);
    if (ret)
    {
        my_bpf_printk("failed to init timer\n");
        return;
    }

    ret = bpf_timer_set_callback(&src_mac_entry->expiration_timer, mac_table_expiration_callback);
    if (ret)
    {
        my_bpf_printk("failed to set timer callback\n");
        return;
    }

    ret = bpf_timer_start(&src_mac_entry->expiration_timer, FIVE_MINUTES_IN_NS, 0);
    if (ret)
    {
        my_bpf_printk("failed to start timer\n");
        return;
    }
}

// --------------------------------------------------------