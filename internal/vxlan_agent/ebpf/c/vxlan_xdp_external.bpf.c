#include "vxlan_common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --------------------------------------------------------

// a LPM trie data structure
// for example 192.168.1.0/24 --> VNI 0

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct network_vni_light);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} networks_light_map SEC(".maps");

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

static long __always_inline handle_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time_ns);
static long __always_inline handle_packet_received_by_external_iface__arp_packet(struct xdp_md *ctx, __u64 current_time_ns, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac);
static long __always_inline handle_packet_received_by_external_iface__ip_packet(struct xdp_md *ctx, __u64 current_time_ns, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac);
static void __always_inline learn_from_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time_ns, struct mac_address *inner_src_mac, __u32 *outer_src_border_ip);

// --------------------------------------------------------
// main xdp entry point

SEC("xdp.frags")
long vxlan_xdp_external(struct xdp_md *ctx)
{
    // we can use current_time_ns as something like a unique identifier for packet
    my_bpf_printk("%d 1. packet received", ctx->ingress_ifindex);
    __u64 current_time_ns = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)ctx->data;

    // check if the packet is valid
    if ((void *)(eth + 1) > (void *)(long)ctx->data_end)
        return XDP_DROP;

    // if packet has been received by an external interface
    return handle_packet_received_by_external_iface(ctx, current_time_ns);
}

// --------------------------------------------------------

static long __always_inline handle_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time_ns)
{
    my_bpf_printk("%d 3. handle packet received by external iface", ctx->ingress_ifindex);
    // if packet has been received by an external interface
    // it means that this packet:
    // - has outer ethernet header
    // - has outer ip header
    // - has outer udp header
    // - has outer vxlan header
    // - has an internal original layer 2 frame
    //      - has inner ethernet header
    //      - has either inner ip packet or arp packet or other type of packet
    //
    // for simplicity we assume that the packet is an ip or arp packet
    // in the future we will add support for other type of packets
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int packet_size = data_end - data;

    my_bpf_printk(". %d 3.1 Packet size: %d bytes\n", ctx->ingress_ifindex, packet_size);

    struct ethhdr *outer_eth = data;
    struct iphdr *outer_iph = data + ETH_HLEN;
    struct udphdr *outer_udph = data + ETH_HLEN + IP_HDR_LEN;
    struct vxlanhdr *outer_vxh = data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN;

    // Ensure the packet is valid
    if ((void *)(outer_vxh + 1) > data_end)
        return XDP_DROP;

    // Extract outer source and destination IP addresses
    __u32 outer_src_ip = outer_iph->saddr;
    __u32 outer_dst_ip = outer_iph->daddr;

    // Calculate the start of the inner Ethernet header
    // when we perform (+1), it will not add 1 to the pointer
    // it will add the size of the vxlan header which is 8 bytes
    // in this case, it will point to the start of the inner ethernet header
    struct ethhdr *inner_eth = data + ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN;

    // Ensure the inner Ethernet header is valid
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    // Extract inner source and destination MAC addresses
    struct mac_address inner_src_mac;
    struct mac_address inner_dst_mac;

    my_bpf_printk("%d 3. the protocol is proto %x", ctx->ingress_ifindex, bpf_ntohs(inner_eth->h_proto));

    __u16 h_proto = bpf_ntohs(inner_eth->h_proto);

    if (h_proto == ETH_P_ARP)
    {
        // if the inner packet is an ARP packet
        my_bpf_printk("%d 3. detected  ARP packet", ctx->ingress_ifindex);

        __builtin_memcpy(inner_src_mac.addr, inner_eth->h_source, ETH_ALEN);
        __builtin_memcpy(inner_dst_mac.addr, inner_eth->h_dest, ETH_ALEN);

        learn_from_packet_received_by_external_iface(ctx, current_time_ns, &inner_src_mac, &outer_src_ip);

        return handle_packet_received_by_external_iface__arp_packet(ctx, current_time_ns, data, data_end, inner_eth, &inner_dst_mac);
    }
    else if (h_proto == ETH_P_IP)
    {
        // if the inner packet is an IP packet
        my_bpf_printk("%d 3. detected  IP packet", ctx->ingress_ifindex);

        __builtin_memcpy(inner_src_mac.addr, inner_eth->h_source, ETH_ALEN);
        __builtin_memcpy(inner_dst_mac.addr, inner_eth->h_dest, ETH_ALEN);

        learn_from_packet_received_by_external_iface(ctx, current_time_ns, &inner_src_mac, &outer_src_ip);

        return handle_packet_received_by_external_iface__ip_packet(ctx, current_time_ns, data, data_end, inner_eth, &inner_dst_mac);
    }
    else
    {
        my_bpf_printk("%d 3.  neither ARP, nor IP detected -> XDP_DROP", ctx->ingress_ifindex);
        my_bpf_printk("inner_eth->h_proto (network byte order) = %x\n", inner_eth->h_proto);
        my_bpf_printk("inner_eth->h_proto (host byte order) = %x\n", bpf_ntohs(inner_eth->h_proto));

        return XDP_DROP;
    }
}

static long __always_inline handle_packet_received_by_external_iface__arp_packet(struct xdp_md *ctx, __u64 current_time_ns, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac)
{

    my_bpf_printk("%d 4. handling ARP packet received by external iface", ctx->ingress_ifindex);

    struct arphdr *inner_arph = (void *)(inner_eth + 1);

    struct in_addr src_ip;

    // Ensure the inner ARP header is valid
    if ((void *)(inner_arph + 1) > data_end)
        return XDP_DROP;

    struct arp_payload *inner_arp_payload = (void *)(inner_arph + 1);

    // Ensure the inner ARP payload is valid
    if ((void *)(inner_arp_payload + 1) > data_end)
        return XDP_DROP;

    // Check if packet really belongs to internal network
    struct ipv4_lpm_key key = {.prefixlen = 32};
    __builtin_memcpy(key.data, inner_arp_payload->ar_tip, sizeof(key.data));

    create_in_addr_from_arp_ip(inner_arp_payload->ar_sip, &src_ip);

    // if the packet is not for internal network do XDP_PASS in here and similar thing in TC
    struct network_vni_light *dst_network_vni = bpf_map_lookup_elem(&networks_light_map, &key);
    if (dst_network_vni == NULL)
    {
        my_bpf_printk("does not belong to internal network. pass it up");
        return XDP_PASS;
    }

    if (!is_ip_in_network(&(dst_network_vni->network), &src_ip))
    {
        my_bpf_printk("does not belong to internal network. pass it up");
        return XDP_PASS;
    };

    my_bpf_printk("%d 4. packet belongs to internal network.", ctx->ingress_ifindex);

    if (inner_arph->ar_op == bpf_htons(ARPOP_REQUEST))
    {
        // if the packet is an arp request:
        // - either a normal arp request
        // - or a gratuitous arp request
        //      - Source IP Address: The IP address of the sender.
        //      - Destination IP Address: The same as the source IP address
        //      - Source MAC Address: The MAC address of the sender.
        //      - Destination MAC Address: is set to broadcast address (ff:ff:ff:ff:ff:ff).
        // we need to perform Flooding, XDP_PASS --> handle in implemented TC flooding hook

        // // because we cannot remove outher_eth & outer_ip & outer_udp & outer_vxlan header in
        // // the tc program, before passing it up to the TC we need to strip these headers off
        // my_bpf_printk("%d 5. remove outer headers before sending the packet to TC", ctx->ingress_ifindex);
        // if (bpf_xdp_adjust_head(ctx, NEW_HDR_LEN))
        //     return XDP_DROP;

        my_bpf_printk("%d 6. sending packet to TC", ctx->ingress_ifindex);

        return XDP_PASS;
    }
    else if (inner_arph->ar_op == bpf_htons(ARPOP_REPLY))
    {

        my_bpf_printk("%d 4. handling arp reply.", ctx->ingress_ifindex);
        // if the packet is an arp reply:
        // - either a normal arp reply
        // - or a gratuitous arp reply
        //      - Source IP Address: The IP address of the sender.
        //      - Destination IP Address: The same as the source IP address
        //      - Source MAC Address: The MAC address of the sender.
        //      - Destination MAC Address: the MAC address of an specific device or broadcast address (ff:ff:ff:ff:ff:ff)
        //          - if we want only an specific device to update its arp cache we set its mac address as the destination mac address
        //          - if we want to update the arp cache of all devices on a subnet we set the destination mac address to broadcast address
        //
        // TODO: i need to make sure that we want to enable Gratuitous ARP replies or not

        // check if it is a gratuitous arp reply
        if (inner_arp_payload->ar_sip == inner_arp_payload->ar_tip && is_broadcast_address(inner_dst_mac))
        {
            // we need to perform Flooding, XDP_PASS --> handle in implemented TC flooding hook

            // // because we cannot remove outher_eth & outer_ip & outer_udp & outer_vxlan header in
            // // the tc program, before passing it up to the TC we need to strip these headers off
            // my_bpf_printk("%d 5. remove outer headers before sending the packet to TC", ctx->ingress_ifindex);
            // if (bpf_xdp_adjust_head(ctx, NEW_HDR_LEN))
            //     return XDP_DROP;

            my_bpf_printk("%d 6. sending packet to TC", ctx->ingress_ifindex);

            return XDP_PASS;
        }

        // Check if the destination MAC address is known
        my_bpf_printk("%d 4. trying to find inner_dst_mac in mac_table", ctx->ingress_ifindex);
        struct mac_table_entry *dst_mac_entry = bpf_map_lookup_elem(&mac_table, inner_dst_mac);
        if (dst_mac_entry != NULL)
        {
            my_bpf_printk("%d 4. found inner_dst_mac in mac_table", ctx->ingress_ifindex);
            __u32 dst_mac_entry_ifindex = dst_mac_entry->ifindex;


            my_bpf_printk("%d 4. try to remove outer header", ctx->ingress_ifindex);
            // Handle ARP reply: remove outer headers and forward
            if (bpf_xdp_adjust_head(ctx, NEW_HDR_LEN))
                return XDP_DROP;

            my_bpf_printk("%d 4. sucessfully removed outer header", ctx->ingress_ifindex);

            // Recalculate data and data_end pointers after adjustment
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            // Ensure the packet is still valid after adjustment
            if (data + sizeof(struct ethhdr) > data_end)
                return XDP_DROP;

            my_bpf_printk("%d 4. trying to redirect to %d, packet size %d", ctx->ingress_ifindex, dst_mac_entry->ifindex, data_end - data);

            // Redirect the resulting internal frame buffer to the proper interface
            return bpf_redirect(dst_mac_entry->ifindex, 0);
        }
        else
        {
            // if we recieve an arp reply packet from external interface that
            // we don't know what to do with it then we need to drop it
            return XDP_DROP;
        }
    }
    else
    {
        // if the packet doesn't have valid ar_op
        return XDP_DROP;
    }
}

static long __always_inline handle_packet_received_by_external_iface__ip_packet(struct xdp_md *ctx, __u64 current_time_ns, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac)
{
    my_bpf_printk("%d 4. handling IP packet received by external iface", ctx->ingress_ifindex);
    // Extract inner source and destination MAC addresses

    // TODO TODO TODO is this correct?
    struct iphdr *inner_iph = (void *)(inner_eth + 1);

    // Ensure the inner IP header is valid
    if ((void *)(inner_iph + 1) > data_end)
        return XDP_DROP;

    // Extract inner source and destination IP addresses
    struct in_addr src_ip;
    __u32 inner_dst_ip = inner_iph->daddr;

    // Check if packet really belongs to internal network
    struct ipv4_lpm_key key = {.prefixlen = 24};

    src_ip.s_addr = bpf_ntohl(inner_iph->saddr);

    __builtin_memcpy(key.data, &inner_dst_ip, sizeof(key.data));

    // if the packet is not for internal network do XDP_PASS here and
    struct network_vni_light *dst_network_vni = bpf_map_lookup_elem(&networks_light_map, &key);
    if (dst_network_vni == NULL)
    {
        my_bpf_printk("does not belong to internal network. pass it up");
        return XDP_PASS;
    }

    if (!is_ip_in_network(&(dst_network_vni->network), &src_ip))
    {
        my_bpf_printk("does not belong to internal network. pass it up");
        return AGENT_PASS;
    };

    struct mac_table_entry *dst_mac_entry = bpf_map_lookup_elem(&mac_table, inner_dst_mac);

    if (dst_mac_entry != NULL)
    {
        __u32 dst_mac_entry_ifindex = dst_mac_entry->ifindex;

        // Remove outer headers by adjusting the headroom
        if (bpf_xdp_adjust_head(ctx, NEW_HDR_LEN))
            return XDP_DROP;

        // Recalculate data and data_end pointers after adjustment
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        // Ensure the packet is still valid after adjustment
        if (data + sizeof(struct ethhdr) > data_end)
            return XDP_DROP;

        // Redirect the resulting internal frame buffer to the proper interface
        return bpf_redirect(dst_mac_entry->ifindex, 0);
    }
    else
    {
        // if we don't know where to send this packet.
        return XDP_DROP;
    }
}

static void __always_inline learn_from_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time_ns, struct mac_address *inner_src_mac, __u32 *outer_src_border_ip)
{
    // in this case we need to learn two things:
    // - the internal mac address of the source
    // - the external source border ip address that this mac address belongs to

    struct mac_table_entry *src_mac_entry = bpf_map_lookup_elem(&mac_table, inner_src_mac);

    if (src_mac_entry != NULL)
    {
        bpf_timer_cancel(&src_mac_entry->expiration_timer);
    }

    src_mac_entry = &(struct mac_table_entry){
        .last_seen_timestamp_ns = current_time_ns,
        .ifindex = ctx->ingress_ifindex,
        .border_ip.s_addr = *outer_src_border_ip,
        .expiration_timer = {}};

    bpf_map_update_elem(&mac_table, inner_src_mac, src_mac_entry, BPF_ANY);

    src_mac_entry = bpf_map_lookup_elem(&mac_table, inner_src_mac);
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

    // 5 minutes
    ret = bpf_timer_start(&src_mac_entry->expiration_timer, FIVE_MINUTES_IN_NS, 0);
    if (ret)
    {
        my_bpf_printk("failed to start timer\n");
        return;
    }
}

// --------------------------------------------------------