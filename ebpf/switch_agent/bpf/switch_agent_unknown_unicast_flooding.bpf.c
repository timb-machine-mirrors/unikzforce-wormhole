#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_INTERFACES 10

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_INTERFACES);
} interfaces_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} interfaces_array_length SEC(".maps");

SEC("tcx/ingress")
int switch_agent_unknown_unicast_flooding(struct __sk_buff *skb)
{
    bpf_printk(
            "///////////////////////////////////////////////////////////////////////////////////////////////////");
    // we can use current_time as something like a unique identifier for packet
    __u64 current_time = bpf_ktime_get_tai_ns();
    struct ethhdr *eth = (void *)(long)skb->data;

    if ((void *)(eth + 1) > (void *)(long)skb->data_end)
        return BPF_DROP;

    bpf_printk(
            "///////////// id = %llu, interface = %d, Packet received, source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            current_time, skb->ingress_ifindex, eth->h_source[0], eth->h_source[1],
            eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    bpf_printk(
            "///////////// id = %llu, interface = %d, Packet received, dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            current_time, skb->ingress_ifindex, eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    int ingress_ifindex = skb->ingress_ifindex;


    int zero = 0; // Key for the first element
    __u32* number_of_interfaces_ptr = bpf_map_lookup_elem(&interfaces_array_length, &zero);
    if (!number_of_interfaces_ptr || *number_of_interfaces_ptr == 0) {
        return TC_ACT_OK;
    }
    __u32 number_of_interfaces = *number_of_interfaces_ptr;

    bpf_printk("///////////// id = %llu, interface = %d, start to multicast\n", current_time, skb->ingress_ifindex);

    if (number_of_interfaces>MAX_INTERFACES)
    {
        number_of_interfaces = MAX_INTERFACES;
    }

    int i;
    __u32* interface_index_ptr;

    i = 0;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 1;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 2;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 3;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 4;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 5;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 6;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 7;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 8;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    i = 9;
    if (i >= number_of_interfaces) {
        return TC_ACT_OK;
    }
    interface_index_ptr = bpf_map_lookup_elem(&interfaces_array, &i);

    if (interface_index_ptr) {
        __u32 interface_index = *interface_index_ptr;

        if (interface_index != ingress_ifindex) {
            bpf_clone_redirect(skb, interface_index, 0);
            bpf_printk("///////////// id = %llu, multicast: redirection to %d \n",
                       current_time, interface_index);
        }
    } else {
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}