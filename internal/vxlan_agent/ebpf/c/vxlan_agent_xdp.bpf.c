#include <linux/if_ether.h>


#include "../../../../include/vmlinux.h"
#include <linux/if_arp.h> // Add this line
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";



#define IP_HDR_LEN sizeof(struct iphdr)
#define UDP_HDR_LEN sizeof(struct udphdr)
#define VXLAN_HDR_LEN sizeof(struct vxlanhdr)
#define NEW_HDR_LEN (ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN)

struct arp_payload {
    unsigned char ar_sha[ETH_ALEN];  // Sender hardware address
    unsigned char ar_sip[4];         // Sender IP address
    unsigned char ar_tha[ETH_ALEN];  // Target hardware address
    unsigned char ar_tip[4];         // Target IP address
};

// --------------------------------------------------------

struct mac_address {
	__u8 mac[ETH_ALEN]; // MAC address
};


// --------------------------------------------------------

struct external_route_info {
    __u32       external_iface_index;
    struct mac_address external_iface_mac;
    struct mac_address external_iface_next_hop_mac;
    struct in_addr     external_iface_ip;
};

// will use these info in case we want to forward a packet to
// external network
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in_addr);
    __type(value, struct external_route_info);
    __uint(max_entries, 4 * 1024);
} border_ip_to_route_info_map SEC(".maps");


// --------------------------------------------------------

// it will tell us whether a iface index is external or internal
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, bool);
    __uint(max_entries, 4 * 1024);
} ifindex_is_internal_map SEC(".maps");


// --------------------------------------------------------

// it will tell us which iface index is responsible for a mac address
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct mac_address);
	__type(value, __u32);
	__uint(max_entries, 4 * 1024 * 1024);
} mac_to_ifindex_map SEC(".maps");


// it will tell us which remote border is responsible for a mac address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mac_address);
    __type(value, struct in_addr);
    __uint(max_entries, 4 * 1024 * 1024);
} mac_to_border_ip_map SEC(".maps");


// it will tell us what is the last time info for a mac has been updated
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct mac_address);
	__type(value, __u64);
	__uint(max_entries, 4 * 1024 * 1024);
} mac_to_timestamp_map SEC(".maps");


// --------------------------------------------------------

// when sending information to userspace code, we will use this format
struct new_discovered_entry {
	struct mac_address mac;
	__u32 ifindex;
	__u64 timestamp;
} *unused_new_discovered_entry __attribute__((unused));
// because new_discovered_entry is not directly mentioned
// as a type in new_discovered_entries_rb then it will be
// omitted in bpf2go generation procedure, unless we
// directly add an unused instance of it to prevent it from
// being omitted by optimization and also in bpf2go generate
// command we must explicitly ask bpf2g to generate this struct
// using '-type new_discovered_entry' option.


// the userspace code will read this ring buffer for new discovered info
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
//	__uint(pinning, LIBBPF_PIN_BY_NAME);
} new_discovered_entries_rb SEC(".maps");


// --------------------------------------------------------


static __always_inline __u16 get_ephemeral_port();
static __always_inline bool is_broadcast_address(const struct mac_address *mac);
static __always_inline struct in_addr convert_to_in_addr(unsigned char ip[4]);


static long __always_inline handle_packet_received_by_internal_iface(struct xdp_md *ctx, struct ethhdr *eth, __u64 current_time);
static void __always_inline add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(struct xdp_md *ctx, struct mac_address* dest_mac_addr);
static void __always_inline learn_from_packet_received_by_internal_iface(const struct xdp_md *ctx, const struct ethhdr *eth, __u64 current_time);

static long __always_inline handle_packet_received_by_external_iface(struct xdp_md *ctx);
static long __always_inline handle_packet_received_by_external_iface__arp_packet(struct xdp_md *ctx, void *data, void *data_end, struct ethhdr *inner_eth);
static long __always_inline handle_packet_received_by_external_iface__ip_packet(struct xdp_md *ctx, void *data, void *data_end, struct ethhdr *inner_eth);


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

    bool* ifindex_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &(ctx->ingress_ifindex));

    if ( ifindex_is_internal == NULL ) {
        return XDP_ABORTED;
    }

    bool packet_is_received_by_internal_iface = *ifindex_is_internal;

    if (packet_is_received_by_internal_iface) {
        // if packet has been received by an internal iface
        return handle_packet_received_by_internal_iface(ctx, eth, current_time);
    } else {
        // if packet has been received by an external interface
        return handle_packet_received_by_external_iface(ctx);
    }
}


// --------------------------------------------------------


// Function to get a random port within the ephemeral range
static __always_inline __u16 get_ephemeral_port() {
    return 49152 + bpf_get_prandom_u32() % (65535 - 49152 + 1);
}

// Function to check if the MAC address is the broadcast address
static __always_inline bool is_broadcast_address(const struct mac_address *mac) {
    // Check if the MAC address is the broadcast address (FF:FF:FF:FF:FF:FF)
    if (mac->mac[0] != 0xFF) return false;
    if (mac->mac[1] != 0xFF) return false;
    if (mac->mac[2] != 0xFF) return false;
    if (mac->mac[3] != 0xFF) return false;
    if (mac->mac[4] != 0xFF) return false;
    if (mac->mac[5] != 0xFF) return false;
    return true;
}

// Function to convert an array of 4 bytes to an in_addr struct
static __always_inline struct in_addr convert_to_in_addr(unsigned char ip[4]) {
    struct in_addr addr;
    addr.s_addr = bpf_ntohl(*(unsigned int *)ip);
    return addr;
}


// --------------------------------------------------------


static long __always_inline handle_packet_received_by_internal_iface(struct xdp_md *ctx, struct ethhdr *eth, __u64 current_time) {
    // if packet has been received by an internal iface
    // it means this packet should have no outer headers.
    // we should:
    // - either forward it internally
    // - or add outer headers and forward it to an external interface

    learn_from_packet_received_by_internal_iface(ctx, eth, current_time);

    struct mac_address dest_mac_addr;
    __builtin_memcpy(dest_mac_addr.mac, eth->h_dest, ETH_ALEN);

    __u32* ifindex_to_redirect = bpf_map_lookup_elem(&mac_to_ifindex_map, &dest_mac_addr);

    if (ifindex_to_redirect != NULL) {
        // if we already know this mac in mac table ( mac_to_ifindex_map )

        bool* ifindex_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, ifindex_to_redirect);

        if ( ifindex_to_redirect_is_internal == NULL ) {
            return XDP_ABORTED;
        }

        bool packet_to_be_redirected_to_an_internal_interface = *ifindex_to_redirect_is_internal;

        if (packet_to_be_redirected_to_an_internal_interface) {
            // if packet need to be forwarded to an internal interface
            return bpf_redirect(*ifindex_to_redirect, 0);
        } else {
            // if packet need to be forwarded to an external interface
            add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(ctx, &dest_mac_addr);

            return bpf_redirect(*ifindex_to_redirect, 0);
        }

    } else {
        // if we don't know this mac in mac table ( mac_to_ifindex_map )
        // no matter why we are here:
        // - either because of a mac addr that we don't know where to find (unknown mac)
        // - or because of broadcast mac address ( FFFFFFFFFFFF )
        // in ether case we must perform Flooding.--> XDP_PASS --> handle in implemented TC flooding hook

        return XDP_PASS;
    }
}

static void __always_inline add_outer_headers_to_internal_packet_before_forwarding_to_external_iface(struct xdp_md *ctx, struct mac_address* dest_mac_addr) {
    // if packet need to be forwarded to an external interface
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr* inner_eth = data;

    struct ethhdr* outer_eth;
    struct iphdr* outer_iph;
    struct udphdr* outer_udph;
    struct vxlanhdr* outer_vxh;

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
    outer_iph = data + ETH_HLEN;          // ETH_HLEN == 14 & ETH_ALEN == 6
    outer_udph = (void*) outer_iph + IP_HDR_LEN;
    outer_vxh = (void*) outer_udph + UDP_HDR_LEN;

    struct in_addr* border_ip = bpf_map_lookup_elem(&mac_to_border_ip_map, dest_mac_addr);

    if (border_ip == NULL) {
        return XDP_ABORTED;
    }

    struct external_route_info* route_info = bpf_map_lookup_elem(&border_ip_to_route_info_map, border_ip);

    if (route_info == NULL) {
        return XDP_ABORTED;
    }

    //  In network programming, the distinction between the endianness of multi-byte values and single-byte values or byte sequences is critical.
    //  - Multi-byte Values: The endianness affects how multi-byte values (such as 16-bit, 32-bit, and 64-bit integers) are stored in memory. Network protocols typically require these values to be in big-endian (network byte order) format.
    //  - Byte Sequences: Single-byte values or sequences of bytes (such as MAC addresses) are not affected by endianness. They are simply copied as they are, byte by byte.
    __builtin_memcpy(outer_eth->h_source, route_info->external_iface_mac.mac, ETH_ALEN);
    __builtin_memcpy(outer_eth->h_dest, route_info->external_iface_next_hop_mac.mac, ETH_ALEN);
    outer_eth->h_proto = bpf_htons(ETH_P_IP);

    outer_iph->version = 4;
    outer_iph->ihl = 5;
    outer_iph->tos = 0;
    outer_iph->tot_len = bpf_htons(new_len - ETH_HLEN);
    outer_iph->id=0;
    outer_iph->frag_off = 0;
    outer_iph->ttl = 64;
    outer_iph->protocol = IPPROTO_UDP;
    outer_iph->check = 0; // will be calculated later
    outer_iph->saddr = bpf_htonl(route_info->external_iface_ip);
    outer_iph->daddr = bpf_htonl(*border_ip);


    outer_udph->source = bpf_htons(get_ephemeral_port()); // Source UDP port
    outer_udph->dest = bpf_htons(4789); // Destination UDP port (VXLAN default)
    outer_udph->len = bpf_htons(new_len - ETH_HLEN - IP_HDR_LEN);
    outer_udph->check = 0; // UDP checksum is optional in IPv4

    // for now we don't set VXLAN header

    // Calculate ip checksum
    outer_iph->check = ~bpf_csum_diff(0, 0, (__u32)outer_iph, IP_HDR_LEN, 0);
}

static void __always_inline learn_from_packet_received_by_internal_iface(const struct xdp_md *ctx, const struct ethhdr *eth, __u64 current_time)
{
    struct mac_address src_mac_addr;
    __builtin_memcpy(src_mac_addr.mac, eth->h_source, ETH_ALEN);

    // Update the mac_to_timestamp_map with the current time
    bpf_map_update_elem(&mac_to_timestamp_map, &src_mac_addr, &current_time, BPF_ANY);

    // Check if the source MAC address is already in the mac_to_ifindex_map
    __u32* ifindex = bpf_map_lookup_elem(&mac_to_ifindex_map, &src_mac_addr);

    if (ifindex == NULL) {
        // If the source MAC address is not in the map
        // it means that this is the first time we see this mac address
        // & we need to report it to new_discovered_entries_rb,
        // this way in the userspace we can learn about this mac address
        // and maintain a timed cache entry for this mac address in our ttl cache in userspace.
        // whenever the cache entry in userspace expires, we will remove it from the kernel map as well.

        struct new_discovered_entry new_entry;
        new_entry.mac = src_mac_addr;
        new_entry.timestamp = current_time;
        new_entry.ifindex = ctx->ingress_ifindex;

        bpf_ringbuf_output(&new_discovered_entries_rb, &new_entry, sizeof(new_entry), 0);
    }

    __u32 ingress_ifindex = ctx->ingress_ifindex;
    bpf_map_update_elem(&mac_to_ifindex_map, &src_mac_addr, &ingress_ifindex, BPF_ANY);
}


// --------------------------------------------------------


static long __always_inline handle_packet_received_by_external_iface(struct xdp_md *ctx) {
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


    if (inner_eth->h_proto == bpf_htons(ETH_P_ARP)) {
        // if the inner packet is an ARP packet
        return handle_packet_received_by_external_iface__arp_packet(ctx, data, data_end, inner_eth);
    } else if (inner_eth->h_proto == bpf_htons(ETH_P_IP)) {
        // if the inner packet is an IP packet
        return handle_packet_received_by_external_iface__ip_packet(ctx, data, data_end, inner_eth);
    } else {
        return XDP_DROP;
    }
}

static long __always_inline handle_packet_received_by_external_iface__ip_packet(struct xdp_md *ctx, void *data, void *data_end, struct ethhdr *inner_eth) {
    // Extract inner source and destination MAC addresses
    struct mac_address inner_src_mac;
    struct mac_address inner_dst_mac;
    __builtin_memcpy(inner_src_mac.mac, inner_eth->h_source, ETH_ALEN);
    __builtin_memcpy(inner_dst_mac.mac, inner_eth->h_dest, ETH_ALEN);


    struct iphdr *inner_iph = (void *)(inner_eth + 1);

    // Ensure the inner IP header is valid
    if ((void *)(inner_iph + 1) > data_end)
        return XDP_DROP;

    // Extract inner source and destination IP addresses
    __u32 inner_src_ip = inner_iph->saddr;
    __u32 inner_dst_ip = inner_iph->daddr;


    __u32* ifindex_to_redirect = bpf_map_lookup_elem(&mac_to_ifindex_map, &inner_dst_mac);

    if (ifindex_to_redirect != NULL) {

        bool* ifindex_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, ifindex_to_redirect);

        if ( ifindex_to_redirect_is_internal == NULL ) {
            return XDP_ABORTED;
        }

        bool packet_to_be_redirected_to_an_internal_interface = *ifindex_to_redirect_is_internal;

        if (packet_to_be_redirected_to_an_internal_interface) {
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
            return bpf_redirect(*ifindex_to_redirect, 0);
        } else {
            return XDP_DROP;
        }

    } else {
        // if we don't know where to send this packet.
        return XDP_DROP;
    }

}

static long __always_inline handle_packet_received_by_external_iface__arp_packet(struct xdp_md *ctx, void *data, void *data_end, struct ethhdr *inner_eth) {
    struct arphdr *inner_arph = (void *)(inner_eth + 1);

    // Ensure the inner ARP header is valid
    if ((void *)(inner_arph + 1) > data_end)
        return XDP_DROP;

    struct arp_payload *inner_arp_payload = (void *)(inner_arph + 1);

    // Ensure the inner ARP payload is valid
    if ((void *)(inner_arp_payload + 1) > data_end)
        return XDP_DROP;

    if (inner_arph->ar_op == bpf_htons(ARPOP_REQUEST)) {
        // if the packet is an arp request:
        // - either a normal arp request
        // - or a gratuitous arp request
        //      - Source IP Address: The IP address of the sender.
        //      - Destination IP Address: The same as the source IP address
        //      - Source MAC Address: The MAC address of the sender.
        //      - Destination MAC Address: is set to broadcast address (ff:ff:ff:ff:ff:ff).
        // we need to perform Flooding, XDP_PASS --> handle in implemented TC flooding hook
        return XDP_PASS;
    } else if (inner_arph->ar_op == bpf_htons(ARPOP_REPLY)) {
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

        // Extract inner source and destination MAC addresses
        struct mac_address inner_src_mac;
        struct mac_address inner_dst_mac;
        __builtin_memcpy(inner_src_mac.mac, inner_eth->h_source, ETH_ALEN);
        __builtin_memcpy(inner_dst_mac.mac, inner_eth->h_dest, ETH_ALEN);

        
        // check if it is a gratuitous arp reply
        if (*(unsigned int *)inner_arp_payload->ar_sip == *(unsigned int *)inner_arp_payload->ar_tip && is_broadcast_address(&inner_dst_mac)) {
            // we need to perform Flooding, XDP_PASS --> handle in implemented TC flooding hook
            return XDP_PASS;
        }

        // Check if the destination MAC address is known
        __u32* ifindex_to_redirect = bpf_map_lookup_elem(&mac_to_ifindex_map, &inner_dst_mac);
        if (ifindex_to_redirect != NULL) {
            bool* ifindex_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, ifindex_to_redirect);

            if ( ifindex_to_redirect_is_internal == NULL ) {
                return XDP_ABORTED;
            }

            bool packet_to_be_redirected_to_an_internal_interface = *ifindex_to_redirect_is_internal;

            if (packet_to_be_redirected_to_an_internal_interface) {
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
                return bpf_redirect(*ifindex_to_redirect, 0);
            } else {
                // if we recieve a arp packet from external interface 
                // that is meant to be redirected to another remote vxlan border agent
                // then we need to drop it
                return XDP_DROP;
            }
        } else {
            // if we recieve an arp reply packet from external interface that
            // we don't know what to do with it then we need to drop it
            return XDP_DROP;
        }
    } else {
        // if the packet doesn't have valid ar_op
        return XDP_DROP;
    }
}


// --------------------------------------------------------
