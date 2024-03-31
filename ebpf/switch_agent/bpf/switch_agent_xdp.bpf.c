#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct mac_address {
	unsigned char mac[ETH_ALEN]; // MAC address
};

struct iface_index {
	__u32 interface_index;
	__u64 timestamp;
};

struct mac_address_iface_entry {
	struct mac_address mac;
	struct iface_index iface;
} *unused_mac_address_iface_entry __attribute__((unused));
// because mac_address_iface_entry is not directly mentioned
// as a type in new_discovered_entries_rb then it will be
// omitted in bpf2go generation procedure, unless we
// directly add an unused instance of it to prevent it from
// being omitted by optimization and also in bpf2go generate
// command we must explicitly ask bpf2g to generate this struct
// using '-type mac_address_iface_entry' option.


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct mac_address);
//	__uint(key_size, sizeof(struct mac_address));
	__type(value, struct iface_index);
//	__uint(value_size, sizeof(struct iface_index));
	__uint(max_entries, 4 * 1024 * 1024);
//	__uint(pinning, LIBBPF_PIN_BY_NAME);
} mac_table SEC(".maps") /*__weak */;
// TODO in above check if lack of __weak would
// create any error in program logic or not,
// if it's creating a problem maybe we should
// change the map to pinned version,
// we don't need more than one instance of
// this map, so probably pinning is the solution

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
//	__uint(pinning, LIBBPF_PIN_BY_NAME);
} new_discovered_entries_rb SEC(".maps") /*__weak */;

void register_source_mac_address_if_required(const struct xdp_md *ctx, const struct ethhdr *eth,
					     __u64 current_time);

SEC("xdp")
long switch_agent_xdp(struct xdp_md *ctx)
{
	bpf_printk(
		"----------------------------------------------------------------------------------------------------");
	// we can use current_time as something like a unique identifier for packet
	__u64 current_time = bpf_ktime_get_tai_ns();

	struct ethhdr *eth = (void *)(long)ctx->data;

	// Additional check after the adjustment
	if ((void *)(eth + 1) > (void *)(long)ctx->data_end)
		return XDP_ABORTED;

	bpf_printk(
		"id = %llu, interface = %d, Packet received, source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		current_time, ctx->ingress_ifindex, eth->h_source[0], eth->h_source[1],
		eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	bpf_printk(
		"id = %llu, interface = %d, Packet received, dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		current_time, ctx->ingress_ifindex, eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

	register_source_mac_address_if_required(ctx, eth, current_time);

	struct mac_address dest_mac_addr;
	__builtin_memcpy(dest_mac_addr.mac, eth->h_dest,
			 ETH_ALEN); // Changed from h_source to h_dest

	bpf_printk(
		"id = %llu, interface = %d, lookup mac_table for matching redirect iface, h_dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		current_time, ctx->ingress_ifindex, eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

	struct iface_index *iface_to_redirect = bpf_map_lookup_elem(&mac_table, &dest_mac_addr);

	if (!iface_to_redirect) {
		bpf_printk(
			"id = %llu, interface = %d, in case eth-h_dest==ff:ff:ff:ff:ff:ff we should do unknown unicast flooding\n",
			current_time, ctx->ingress_ifindex);
		// Unknown Unicast Flooding:
		// in this case we need to redirect to interfaces that is not equal to ctx->ingress_ifindex,
		// but normal xdp program at this layer can only redirect a network packet to a single interface,
		// So we should pass it to upper layer. another ebpf program at TC layer should handle redirection.
		// cause in TC layer we can clone a packet and redirect it to more than one network interface.
		return XDP_PASS;

		// TODO: check if the number of network interfaces was just 2 then we don't need TC for UNKNOWN UNICAST FLOODING
		// TODO: because in this case we would only need to redirect to one other network interface, so we can handle redirection
		// TODO: just here

		//		if (ctx->ingress_ifindex != first_interface) {
		//			bpf_printk("id = %llu, interface = %d, redirecting to interface %d \n", current_time, ctx->ingress_ifindex, first_interface);
		//			return bpf_redirect(first_interface, 0);
		//		}
		//		else if (ctx->ingress_ifindex != second_interface) {
		//			bpf_printk("id = %llu, interface = %d, redirecting to interface %d \n", current_time, ctx->ingress_ifindex, second_interface);
		//			return bpf_redirect(second_interface, 0);
		//		} else {
		//			bpf_printk("id = %llu, interface = %d, nothing has been found so will do XDP_PASS\n", current_time, ctx->ingress_ifindex);
		//			return XDP_PASS; // If the destination MAC isn't found, simply pass the packet
		//		}
	}

	bpf_printk("id = %llu, interface = %d, match found. do the redirection\n", current_time,
		   ctx->ingress_ifindex);
	return bpf_redirect(iface_to_redirect->interface_index, 0);
}

void register_source_mac_address_if_required(const struct xdp_md *ctx, const struct ethhdr *eth,
					     __u64 current_time)
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
