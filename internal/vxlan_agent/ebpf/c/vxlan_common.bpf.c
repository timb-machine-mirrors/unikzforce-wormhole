#include "vxlan_common.bpf.h"

// to force the bpf2go to generate go struct for these types
// we have to create some dummy maps for these types
GENERATE_DUMMY_MAP(in_addr)
GENERATE_DUMMY_MAP(external_route_info)
GENERATE_DUMMY_MAP(mac_address)
GENERATE_DUMMY_MAP(mac_table_entry)
GENERATE_DUMMY_MAP(ipv4_lpm_key)
GENERATE_DUMMY_MAP(internal_network_vni)