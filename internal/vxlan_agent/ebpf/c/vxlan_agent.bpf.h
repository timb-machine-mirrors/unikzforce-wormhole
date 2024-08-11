#ifndef VXLAN_AGENT_BPF_H
#define VXLAN_AGENT_BPF_H

#include <linux/if_ether.h>
#include "../../../../include/vmlinux.h"

#define IP_HDR_LEN sizeof(struct iphdr)
#define UDP_HDR_LEN sizeof(struct udphdr)
#define VXLAN_HDR_LEN sizeof(struct vxlanhdr)
#define NEW_HDR_LEN (ETH_HLEN + IP_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN)

struct mac_address {
	__u8 mac[ETH_ALEN]; // MAC address
};

struct external_route_info {
    __u32       external_iface_index;
    struct mac_address external_iface_mac;
    struct mac_address external_iface_next_hop_mac;
    struct in_addr     external_iface_ip;
};

struct arp_payload {
    unsigned char ar_sha[ETH_ALEN];  // Sender hardware address
    unsigned char ar_sip[4];         // Sender IP address
    unsigned char ar_tha[ETH_ALEN];  // Target hardware address
    unsigned char ar_tip[4];         // Target IP address
};

#endif