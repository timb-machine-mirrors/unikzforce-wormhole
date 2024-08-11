#include "vxlan_agent.bpf.h"
#include <linux/if_ether.h>
#include <linux/time.h>

#include "../../../../include/vmlinux.h"
#include <linux/if_arp.h> // Add this line
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define FIVE_MINUTES_IN_NS 300000000000

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

// it will tell us whether a iface index is external or internal
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, bool);
    __uint(max_entries, 4 * 1024);
} ifindex_is_internal_map SEC(".maps");

// --------------------------------------------------------

struct mac_table_entry
{
    __u32 ifindex;                     // interface which mac address is learned from
    __u64 last_seen_timestamp;         // last time this mac address was seen
    struct in_addr border_ip;          // remote agent border ip address that this mac address is learned from.
                                       // - in case of an internal mac address, this field is not used and set to 0.0.0.0
                                       // - in case of an external mac address, this field is used and set to the remote agent border ip address
    struct bpf_timer expiration_timer; // the timer object to expire this mac entry from the map in the future
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mac_address);
    __type(value, struct mac_table_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4 * 1024 * 1024);
} mac_table SEC(".maps");

// --------------------------------------------------------

static __always_inline __u16 get_ephemeral_port();
static __always_inline bool is_broadcast_address(const struct mac_address *mac);
static __always_inline struct in_addr convert_to_in_addr(unsigned char ip[4]);

static int mac_table_expiration_callback(void *map, struct mac_address *key, struct mac_table_entry *value);

static long __always_inline handle_packet_received_by_internal_iface(struct xdp_md *ctx, __u64 current_time, struct ethhdr *eth);
static void __always_inline add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(struct xdp_md *ctx, struct mac_address *dst_mac, struct mac_table_entry *dst_mac_entry);
static void __always_inline learn_from_packet_received_by_internal_iface(const struct xdp_md *ctx, __u64 current_time, struct mac_address *src_mac);

static long __always_inline handle_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time);
static long __always_inline handle_packet_received_by_external_iface__arp_packet(struct xdp_md *ctx, __u64 current_time, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac);
static long __always_inline handle_packet_received_by_external_iface__ip_packet(struct xdp_md *ctx, __u64 current_time, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac);
static void __always_inline learn_from_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time, struct mac_address *inner_src_mac, __u32 *outer_src_border_ip);

// --------------------------------------------------------
// main xdp entry point

SEC("xdp")
long vxlan_agent_xdp(struct xdp_md *ctx)
{
    // we can use current_time as something like a unique identifier for packet
    __u64 current_time = bpf_ktime_get_tai_ns();

    struct ethhdr *eth = (void *)(long)ctx->data;

    // check if the packet is valid
    if ((void *)(eth + 1) > (void *)(long)ctx->data_end)
        return XDP_DROP;

    bool *ifindex_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &(ctx->ingress_ifindex));

    if (ifindex_is_internal == NULL)
    {
        return XDP_ABORTED;
    }

    bool packet_is_received_by_internal_iface = *ifindex_is_internal;

    if (packet_is_received_by_internal_iface)
    {
        // if packet has been received by an internal iface
        return handle_packet_received_by_internal_iface(ctx, eth, current_time);
    }
    else
    {
        // if packet has been received by an external interface
        return handle_packet_received_by_external_iface(ctx, current_time);
    }
}

// --------------------------------------------------------

// Function to get a random port within the ephemeral range
static __always_inline __u16 get_ephemeral_port()
{
    return 49152 + bpf_get_prandom_u32() % (65535 - 49152 + 1);
}

// Function to check if the MAC address is the broadcast address
static __always_inline bool is_broadcast_address(const struct mac_address *mac)
{
    // Check if the MAC address is the broadcast address (FF:FF:FF:FF:FF:FF)
    if (mac->mac[0] != 0xFF)
        return false;
    if (mac->mac[1] != 0xFF)
        return false;
    if (mac->mac[2] != 0xFF)
        return false;
    if (mac->mac[3] != 0xFF)
        return false;
    if (mac->mac[4] != 0xFF)
        return false;
    if (mac->mac[5] != 0xFF)
        return false;
    return true;
}

// Function to convert an array of 4 bytes to an in_addr struct
static __always_inline struct in_addr convert_to_in_addr(unsigned char ip[4])
{
    struct in_addr addr;
    addr.s_addr = bpf_ntohl(*(unsigned int *)ip);
    return addr;
}

// Define the callback function for the timer
static int mac_table_expiration_callback(void *map, struct mac_address *key, struct mac_table_entry *value)
{
    __u64 current_time = bpf_ktime_get_tai_ns();

    if (current_time - value->last_seen_timestamp > FIVE_MINUTES_IN_NS)
    {
        // if the mac entry is expired
        bpf_map_delete_elem(map, key);
    }
    else
    {
        bpf_timer_start(&value->expiration_timer, FIVE_MINUTES_IN_NS, 0);
    }

    return 0;
}

// --------------------------------------------------------

static long __always_inline handle_packet_received_by_internal_iface(struct xdp_md *ctx, __u64 current_time, struct ethhdr *eth)
{
    // if packet has been received by an internal iface
    // it means this packet should have no outer headers.
    // we should:
    // - either forward it internally
    // - or add outer headers and forward it to an external interface

    struct mac_address src_mac;
    __builtin_memcpy(src_mac.mac, eth->h_source, ETH_ALEN);

    learn_from_packet_received_by_internal_iface(ctx, eth, current_time);

    struct mac_address dst_mac;
    __builtin_memcpy(dst_mac.mac, eth->h_dest, ETH_ALEN);

    struct mac_table_entry *dst_mac_entry = bpf_map_lookup_elem(&mac_table, &dst_mac);

    if (dst_mac_entry != NULL)
    {
        // if we already know this dest mac in mac_table

        bool *ifindex_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &(dst_mac_entry->ifindex));

        if (ifindex_to_redirect_is_internal == NULL)
        {
            return XDP_ABORTED;
        }

        bool packet_to_be_redirected_to_an_internal_interface = *ifindex_to_redirect_is_internal;

        if (packet_to_be_redirected_to_an_internal_interface)
        {
            // if packet need to be forwarded to an internal interface
            return bpf_redirect(dst_mac_entry->ifindex, 0);
        }
        else
        {
            // if packet need to be forwarded to an external interface
            add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(ctx, &dst_mac, dst_mac_entry);

            return bpf_redirect(dst_mac_entry->ifindex, 0);
        }
    }
    else
    {
        // if we don't know this dest mac in mac_table
        // no matter why we are here:
        // - either because of a dest mac addr that we don't know where to find (unknown dest mac)
        // - or because dest mac is broadcast mac address ( FFFFFFFFFFFF )
        // in ether case we must perform Flooding --> XDP_PASS --> handle in implemented TC flooding hook

        return XDP_PASS;
    }
}

static void __always_inline add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(struct xdp_md *ctx, struct mac_address *dst_mac, struct mac_table_entry *dst_mac_entry)
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
        return XDP_DROP;

    // Recalculate data and data_end pointers after adjustment
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // Ensure the packet is still valid after adjustment
    if (data + new_len > data_end)
        return XDP_DROP;

    outer_eth = data;
    outer_iph = data + ETH_HLEN; // ETH_HLEN == 14 & ETH_ALEN == 6
    outer_udph = (void *)outer_iph + IP_HDR_LEN;
    outer_vxh = (void *)outer_udph + UDP_HDR_LEN;

    struct in_addr *dst_border_ip = &(dst_mac_entry->border_ip);

    // if (dst_border_ip == NULL) {
    //     // we are in add_outer_headers...() function, it means that we have an ifindex in mac_to_ifindex_map
    //     // which is an external ifindex, but we don't know the border ip address of the destination mac address.
    //     // this should never happen, because we update mac_to_border_ip_map in the same function
    //     // where we update mac_to_ifindex_map.
    //     //
    //     // so in case this happens, we perform XDP_ABORTED because it means something is fishy.
    //     return XDP_ABORTED;
    // }

    struct external_route_info *route_info = bpf_map_lookup_elem(&border_ip_to_route_info_map, dst_border_ip);

    if (route_info == NULL)
    {
        // we must have prepopulated route_info in border_ip_to_route_info_map before starting the xdp program.
        // if we don't have it, it means that something is fishy, and we must abort the packet.
        return XDP_ABORTED;
    }

    //  In network programming, the distinction between the endianness of multi-byte values and byte sequences is critical.
    //  - Multi-byte Values: The endianness affects how multi-byte values (such as 16-bit, 32-bit, and 64-bit integers) are stored
    //    in memory. Network protocols typically require these values to be in big-endian (network byte order) format.
    //    Multi-byte values needs to be handled by bpf_htons() or bpf_htonl(). Like IP addresses, which is a single 32-bit value.
    //  - Byte Sequences: sequences of bytes (such as MAC addresses) are not affected by endianness.
    //    They are simply copied as they are, byte by byte. Like mac addresses, which is a 6 bytes sequence.
    __builtin_memcpy(outer_eth->h_source, route_info->external_iface_mac.mac, ETH_ALEN);        // mac address is a byte sequence, not affected by endianness
    __builtin_memcpy(outer_eth->h_dest, route_info->external_iface_next_hop_mac.mac, ETH_ALEN); // mac address is a byte sequence, not affected by endianness
    outer_eth->h_proto = bpf_htons(ETH_P_IP);                                                   // ip address is a multi-byte value, so it needs to be in network byte order

    outer_iph->version = 4;                                      // ip version
    outer_iph->ihl = 5;                                          // ip header length
    outer_iph->tos = 0;                                          // ip type of service
    outer_iph->tot_len = bpf_htons(new_len - ETH_HLEN);          // ip total length
    outer_iph->id = 0;                                           // ip id
    outer_iph->frag_off = 0;                                     // ip fragment offset
    outer_iph->ttl = 64;                                         // ip time to live
    outer_iph->protocol = IPPROTO_UDP;                           // ip protocol
    outer_iph->check = 0;                                        // ip checksum will be calculated later
    outer_iph->saddr = bpf_htonl(route_info->external_iface_ip); // ip source address
    outer_iph->daddr = bpf_htonl(*dst_border_ip);                // ip destination address

    outer_udph->source = bpf_htons(get_ephemeral_port());         // Source UDP port
    outer_udph->dest = bpf_htons(4789);                           // Destination UDP port (VXLAN default)
    outer_udph->len = bpf_htons(new_len - ETH_HLEN - IP_HDR_LEN); // UDP length
    outer_udph->check = 0;                                        // UDP checksum is optional in IPv4

    // for now we don't set VXLAN header

    // Calculate ip checksum
    outer_iph->check = ~bpf_csum_diff(0, 0, (__u32)outer_iph, IP_HDR_LEN, 0);
}

static void __always_inline learn_from_packet_received_by_internal_iface(const struct xdp_md *ctx, __u64 current_time, struct mac_address *src_mac)
{
    struct mac_table_entry *src_mac_entry = bpf_map_lookup_elem(&mac_table, &src_mac);

    if (src_mac_entry == NULL)
    {
        // if the source mac address is not in the mac table, we need to insert it
        src_mac_entry = &(struct mac_table_entry){
            .last_seen_timestamp = current_time,
            .ifindex = ctx->ingress_ifindex,
            .border_ip = {0}, // in this case, border_ip is set to 0.0.0.0 but it doesn't mean it's really 0.0.0.0 but it means it's not set yet.
            .expiration_timer = {}};

        bpf_map_update_elem(&mac_table, &src_mac, src_mac_entry, BPF_ANY);

        int ret;
        ret = bpf_timer_init(&src_mac_entry->expiration_timer, &mac_table, CLOCK_BOOTTIME);
        if (ret)
        {
            bpf_printk("failed to init timer\n");
            return;
        }

        ret = bpf_timer_set_callback(&src_mac_entry->expiration_timer, mac_table_expiration_callback);
        if (ret)
        {
            bpf_printk("failed to set timer callback\n");
            return;
        }

        // 5 minutes
        ret = bpf_timer_start(&src_mac_entry->expiration_timer, FIVE_MINUTES_IN_NS, 0);
        if (ret)
        {
            bpf_printk("failed to start timer\n");
            return;
        }
    }
    else
    {
        src_mac_entry->last_seen_timestamp = current_time;

        bpf_map_update_elem(&mac_table, &src_mac, src_mac_entry, BPF_ANY);
    }
}

// --------------------------------------------------------

static long __always_inline handle_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time)
{
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

    struct ethhdr *outer_eth = data;
    struct iphdr *outer_iph = data + sizeof(struct ethhdr);
    struct udphdr *outer_udph = (void *)outer_iph + sizeof(struct iphdr);
    struct vxlanhdr *outer_vxh = (void *)outer_udph + sizeof(struct udphdr);

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
    struct ethhdr *inner_eth = (void *)(outer_vxh + 1);

    // Ensure the inner Ethernet header is valid
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    // Extract inner source and destination MAC addresses
    struct mac_address inner_src_mac;
    struct mac_address inner_dst_mac;

    if (inner_eth->h_proto == bpf_htons(ETH_P_ARP))
    {
        // if the inner packet is an ARP packet

        __builtin_memcpy(inner_src_mac.mac, inner_eth->h_source, ETH_ALEN);
        __builtin_memcpy(inner_dst_mac.mac, inner_eth->h_dest, ETH_ALEN);

        learn_from_packet_received_by_external_iface(ctx, current_time, &inner_src_mac, outer_src_ip);

        return handle_packet_received_by_external_iface__arp_packet(ctx, current_time, data, data_end, inner_eth, &inner_dst_mac);
    }
    else if (inner_eth->h_proto == bpf_htons(ETH_P_IP))
    {
        // if the inner packet is an IP packet

        __builtin_memcpy(inner_src_mac.mac, inner_eth->h_source, ETH_ALEN);
        __builtin_memcpy(inner_dst_mac.mac, inner_eth->h_dest, ETH_ALEN);

        learn_from_packet_received_by_external_iface(ctx, current_time, &inner_src_mac, outer_src_ip);

        return handle_packet_received_by_external_iface__ip_packet(ctx, current_time, data, data_end, inner_eth, &inner_dst_mac);
    }
    else
    {
        return XDP_DROP;
    }
}

static long __always_inline handle_packet_received_by_external_iface__arp_packet(struct xdp_md *ctx, __u64 current_time, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac)
{

    struct arphdr *inner_arph = (void *)(inner_eth + 1);

    // Ensure the inner ARP header is valid
    if ((void *)(inner_arph + 1) > data_end)
        return XDP_DROP;

    struct arp_payload *inner_arp_payload = (void *)(inner_arph + 1);

    // Ensure the inner ARP payload is valid
    if ((void *)(inner_arp_payload + 1) > data_end)
        return XDP_DROP;

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
        return XDP_PASS;
    }
    else if (inner_arph->ar_op == bpf_htons(ARPOP_REPLY))
    {
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
        if (*(unsigned int *)inner_arp_payload->ar_sip == *(unsigned int *)inner_arp_payload->ar_tip && is_broadcast_address(&inner_dst_mac))
        {
            // we need to perform Flooding, XDP_PASS --> handle in implemented TC flooding hook
            return XDP_PASS;
        }

        // Check if the destination MAC address is known
        struct mac_table_entry *dst_mac_entry = bpf_map_lookup_elem(&mac_table, &inner_dst_mac);
        if (dst_mac_entry != NULL)
        {
            bool *ifindex_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &(dst_mac_entry->ifindex));

            if (ifindex_to_redirect_is_internal == NULL)
            {
                return XDP_ABORTED;
            }

            bool packet_to_be_redirected_to_an_internal_interface = *ifindex_to_redirect_is_internal;

            if (packet_to_be_redirected_to_an_internal_interface)
            {
                // Handle ARP reply: remove outer headers and forward
                if (bpf_xdp_adjust_head(ctx, NEW_HDR_LEN))
                    return XDP_DROP;

                // Recalculate data and data_end pointers after adjustment
                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                // Ensure the packet is still valid after adjustment
                if (data + (data_end - data) > data_end)
                    return XDP_DROP;

                // Redirect the resulting internal frame buffer to the proper interface
                return bpf_redirect(dst_mac_entry->ifindex, 0);
            }
            else
            {
                // if we recieve a arp packet from external interface
                // that is meant to be redirected to another remote vxlan border agent
                // then we need to drop it
                return XDP_DROP;
            }
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

static long __always_inline handle_packet_received_by_external_iface__ip_packet(struct xdp_md *ctx, __u64 current_time, void *data, void *data_end, struct ethhdr *inner_eth, struct mac_address *inner_dst_mac)
{
    // Extract inner source and destination MAC addresses

    struct iphdr *inner_iph = (void *)(inner_eth + 1);

    // Ensure the inner IP header is valid
    if ((void *)(inner_iph + 1) > data_end)
        return XDP_DROP;

    // Extract inner source and destination IP addresses
    __u32 inner_src_ip = inner_iph->saddr;
    __u32 inner_dst_ip = inner_iph->daddr;

    struct mac_table_entry *dst_mac_entry = bpf_map_lookup_elem(&mac_table, &inner_dst_mac);

    if (dst_mac_entry != NULL)
    {

        bool *ifindex_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &(dst_mac_entry->ifindex));

        if (ifindex_to_redirect_is_internal == NULL)
        {
            return XDP_ABORTED;
        }

        bool packet_to_be_redirected_to_an_internal_interface = *ifindex_to_redirect_is_internal;

        if (packet_to_be_redirected_to_an_internal_interface)
        {
            // Remove outer headers by adjusting the headroom
            if (bpf_xdp_adjust_head(ctx, NEW_HDR_LEN))
                return XDP_DROP;

            // Recalculate data and data_end pointers after adjustment
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;

            // Ensure the packet is still valid after adjustment
            if (data + (data_end - data) > data_end)
                return XDP_DROP;

            // Redirect the resulting internal frame buffer to the proper interface
            return bpf_redirect(dst_mac_entry->ifindex, 0);
        }
        else
        {
            return XDP_DROP;
        }
    }
    else
    {
        // if we don't know where to send this packet.
        return XDP_DROP;
    }
}

static void __always_inline learn_from_packet_received_by_external_iface(struct xdp_md *ctx, __u64 current_time, struct mac_address *inner_src_mac, __u32 *outer_src_border_ip)
{
    // in this case we need to learn two things:
    // - the internal mac address of the source
    // - the external source border ip address that this mac address belongs to

    struct mac_table_entry *src_mac_entry = bpf_map_lookup_elem(&mac_table, inner_src_mac);
    if (src_mac_entry == NULL)
    {
        src_mac_entry = &(struct mac_table_entry){
            .last_seen_timestamp = current_time,
            .ifindex = ctx->ingress_ifindex,
            .border_ip.s_addr = *outer_src_border_ip,
            .expiration_timer = {}};

        bpf_map_update_elem(&mac_table, inner_src_mac, src_mac_entry, BPF_ANY);

        int ret;
        ret = bpf_timer_init(&src_mac_entry->expiration_timer, &mac_table, CLOCK_BOOTTIME);
        if (ret)
        {
            bpf_printk("failed to init timer\n");
            return;
        }

        ret = bpf_timer_set_callback(&src_mac_entry->expiration_timer, mac_table_expiration_callback);
        if (ret)
        {
            bpf_printk("failed to set timer callback\n");
            return;
        }

        // 5 minutes
        ret = bpf_timer_start(&src_mac_entry->expiration_timer, FIVE_MINUTES_IN_NS, 0);
        if (ret)
        {
            bpf_printk("failed to start timer\n");
            return;
        }
    }
    else
    {
        src_mac_entry->last_seen_timestamp = current_time;

        bpf_map_update_elem(&mac_table, inner_src_mac, src_mac_entry, BPF_ANY);
    }
}

// --------------------------------------------------------
