#ifndef VXLAN_AGENT_BPF_H
#define VXLAN_AGENT_BPF_H

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
    __u32 data;
};

struct internal_network_vni
{
    __u32 vni;
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

#endif