// #include <linux/bpf.h>
#include <linux/if_ether.h>
// #include <linux/in.h>
// #include <linux/ip.h>
// #include <linux/udp.h>
// #include <linux/if_tunnel.h>

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";



#define IP_HDR_LEN sizeof(struct iphdr)
#define UDP_HDR_LEN sizeof(struct udphdr)
#define VXLAN_HDR_LEN sizeof(struct vxlanhdr)
#define NEW_HDR_LEN (ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN)

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

// Function to get a random port within the ephemeral range
static __always_inline __u16 get_ephemeral_port() {
    return 49152 + bpf_get_prandom_u32() % (65535 - 49152 + 1);
}


SEC("xdp")
long vxlan_agent_xdp(struct xdp_md *ctx)
{
    // we can use current_time as something like a unique identifier for packet
	__u64 current_time = bpf_ktime_get_tai_ns();

	struct ethhdr *eth = (void *)(long)ctx->data;

	// Additional check after the adjustment
	if ((void *)(eth + 1) > (void *)(long)ctx->data_end)
		return XDP_DROP;

    bool* iface_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, &(ctx->ingress_ifindex));

    if ( iface_is_internal == NULL ) {
        return XDP_ABORTED;
    }

    bool packet_is_received_by_internal_interface = *iface_is_internal;

    if (packet_is_received_by_internal_interface) {
        // if packet has been received by an internal iface

        learn_internal_source_host(ctx, eth, current_time);

        struct mac_address dest_mac_addr;
        __builtin_memcpy(dest_mac_addr.mac, eth->h_dest, ETH_ALEN);

        __u32* iface_to_redirect = bpf_map_lookup_elem(&mac_to_ifindex_map, &dest_mac_addr);

        if (iface_to_redirect != NULL) {
            // if we already know this mac in mac table ( mac_to_ifindex_map )

            bool* iface_to_redirect_is_internal = bpf_map_lookup_elem(&ifindex_is_internal_map, iface_to_redirect);

            if ( iface_to_redirect_is_internal == NULL ) {
                return XDP_ABORTED;
            }

            bool packet_to_be_redirected_to_an_internal_interface = *iface_to_redirect_is_internal;

            if (packet_to_be_redirected_to_an_internal_interface) {
                // if packet need to be forwarded to an internal interface
                return bpf_redirect(*iface_to_redirect, 0);
            } else {
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

                // Resize the packet buffer by increasing the headroom
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

                struct in_addr* border_ip = bpf_map_lookup_elem(&mac_to_border_ip_map, &dest_mac_addr);

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

        } else {
            // if we don't know this mac in mac table ( mac_to_ifindex_map )
            // no matter why we are here:
            // - either because of a mac addr that we don't know where to find (unknown mac)
            // - or because of broadcast mac address ( FFFFFF )
            // in ether case we must perform Flooding.--> XDP_PASS --> handle in TC

            return XDP_PASS;
        }

    } else {

    }
}


void learn_internal_source_host(const struct xdp_md *ctx, const struct ethhdr *eth, __u64 current_time)
{
	bpf_printk("id = %llu, learning-process: register source mac address if required\n",
		   current_time);
	struct mac_address source_mac_addr;
	__builtin_memcpy(source_mac_addr.mac, eth->h_source, ETH_ALEN);

	bpf_printk(
		"id = %llu, learning-process: check if we already have registered source mac address \n",
		current_time);

	struct iface_index *iface_for_source_mac =
		bpf_map_lookup_elem(&mac_table, &source_mac_addr);

	if (!iface_for_source_mac) {
		bpf_printk(
			"id = %llu, learning-process: have NOT Found an already registered entry for source mac address \n",
			current_time);

		struct mac_address_iface_entry new_entry;
		__builtin_memset(&new_entry, 0, sizeof(new_entry));

		__builtin_memcpy(new_entry.mac.mac, eth->h_source, ETH_ALEN);
		new_entry.iface.interface_index = ctx->ingress_ifindex;
		new_entry.iface.timestamp = current_time;

		bpf_printk(
			"id = %llu, learning-process: have NOT found + trying to update mac_table map\n",
			current_time);

		bpf_map_update_elem(&mac_table, &(new_entry.mac), &(new_entry.iface), BPF_ANY);
		//		bpf_ringbuf_submit(new_entry, 0);

		bpf_printk(
			"id = %llu, learning-process: have NOT found + trying to submit data to new_discovered map\n",
			current_time);
		bpf_ringbuf_output(&new_discovered_entries_rb, &new_entry, sizeof(new_entry), 0);
	} else {
		bpf_printk(
			"id = %llu, learning-process: have Found an already registered entry for source mac address \n",
			current_time);
		iface_for_source_mac->timestamp = current_time;
		bpf_map_update_elem(&mac_table, &source_mac_addr, iface_for_source_mac, BPF_ANY);
	}
}
