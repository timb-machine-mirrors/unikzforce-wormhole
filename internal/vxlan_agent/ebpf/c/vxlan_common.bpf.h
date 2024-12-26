#ifndef VXLAN_COMMON_BPF_H
#define VXLAN_COMMON_BPF_H

#include "../../../../include/vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_SHOT 2
#define TC_ACT_OK 0

#define ETH_P_IP 0x0800  /* Internet Protocol packet */
#define ETH_P_ARP 0x0806 /* Address Resolution packet */

#define ARPOP_REQUEST 1 /* ARP request */
#define ARPOP_REPLY 2   /* ARP reply */

#define CLOCK_BOOTTIME 7 /* Monotonic system-wide clock that includes time spent in suspension.  */

#define ETH_ALEN 6  /* Ethernet address length */
#define ETH_HLEN 14 /* Total octets in header.	 */
#define IP_HDR_LEN (int)sizeof(struct iphdr)
#define UDP_HDR_LEN (int)sizeof(struct udphdr)
#define VXLAN_HDR_LEN (int)sizeof(struct vxlanhdr)
#define NEW_HDR_LEN (ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN)

#define FIVE_MINUTES_IN_NS 20000000000

static volatile const struct
{
    char hostname[64];
} vxlan_agent_metadata SEC(".rodata");

#define my_bpf_printk(fmt, args...) bpf_printk("%s :::: " fmt, vxlan_agent_metadata.hostname, ##args)

enum vxlan_agent_processing_error
{
    AGENT_ERROR_ABORT = 0,
    AGENT_ERROR_DROP = 1,
    AGENT_NO_ERROR = 2,
};

struct mac_table_entry
{
    struct bpf_timer expiration_timer; // the timer object to expire this mac entry from the map in 5 minutes
    __u32 ifindex;                     // interface which mac address is learned from
    __u64 last_seen_timestamp_ns;      // last time this mac address was seen
    struct in_addr border_ip;          // remote agent border ip address that this mac address is learned from.
                                       // - in case of an internal mac address, this field is not used and set to 0.0.0.0
                                       // - in case of an external mac address, this field is used and set to the remote agent border ip address
};

struct external_route_info
{
    __u32 external_iface_index;
    struct mac_address external_iface_mac;
    struct mac_address external_iface_next_hop_mac;
    struct in_addr external_iface_ip;
};

struct arp_payload
{
    unsigned char ar_sha[ETH_ALEN]; // Sender hardware address
    unsigned char ar_sip[4];        // Sender IP address
    unsigned char ar_tha[ETH_ALEN]; // Target hardware address
    unsigned char ar_tip[4];        // Target IP address
};

struct ipv4_lpm_key
{
    __u32 prefixlen;
    __u8  data[4];
};

#define MAX_INTERNAL_IFINDEXES 10
#define MAX_BORDER_IPS 10

struct network_vni
{
    __u32 vni;
    struct ipv4_lpm_key network;
    __u32 internal_ifindexes[MAX_INTERNAL_IFINDEXES];
    __u32 internal_ifindexes_size;
    struct in_addr border_ips[MAX_BORDER_IPS];
    __u32 border_ips_size;
};

struct network_vni_light
{
    __u32 vni;
    struct ipv4_lpm_key network;
};

// Function to get a random port within the ephemeral range
static __always_inline __u16
get_ephemeral_port()
{
    return 49152 + bpf_get_prandom_u32() % (65535 - 49152 + 1);
}

// --------------------------------------------------------

// Function to check if the MAC address is the broadcast address
static __always_inline bool is_broadcast_address(const struct mac_address *mac)
{
    // Check if the MAC address is the broadcast address (FF:FF:FF:FF:FF:FF)
    if (mac->addr[0] != 0xFF)
        return false;
    if (mac->addr[1] != 0xFF)
        return false;
    if (mac->addr[2] != 0xFF)
        return false;
    if (mac->addr[3] != 0xFF)
        return false;
    if (mac->addr[4] != 0xFF)
        return false;
    if (mac->addr[5] != 0xFF)
        return false;
    return true;
}


// the mac table expiration callback function
static int mac_table_expiration_callback(void *map, struct mac_address *key, struct mac_table_entry *value)
{
    __u64 passed_time = bpf_ktime_get_tai_ns() - value->last_seen_timestamp_ns;

    if (passed_time >= FIVE_MINUTES_IN_NS)
    {
        // if the mac entry is expired
        bpf_map_delete_elem(map, key);
    }
    else
    {
        // if the mac entry is not expired we need to restart the timer according to the remaining time
        bpf_timer_start(&value->expiration_timer, FIVE_MINUTES_IN_NS - passed_time, 0);
    }

    return 0;
}

#define GENERATE_DUMMY_MAP(type_name)                                    \
    struct {                                                             \
        __uint(type, BPF_MAP_TYPE_HASH);                                 \
        __uint(max_entries, 1);                                          \
        __type(key, int);                                                \
        __type(value, struct type_name);                                      \
    } dummy_##type_name SEC(".maps");


#endif