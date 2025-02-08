# Wormhole Project

This project tends be a toy implementation of the **VXLAN** protocol with __unknown unicast flooding__ technique using **eBPF XDP/TC**.
Please note that I am not a network engineer, and some of my assumptions about the VXLAN protocol may be incorrect. This project is not intended to be fully compliant with the VXLAN protocol; rather, it aims to create a proof of concept for an eBPF-based VXLAN and demonstrate how VXLAN building blocks can be implemented using eBPF.

using eBPF we can bypass linux kernel networking stack, so it will consume less cpu cycles + it's faster.

## Technologies Used
- Golang/C
- Cilium eBPF
- bpf2go
- Containerlab
- go testing + Ginkgo library
- Edge Shark
- Devcontainer
- docker in docker

## Short explanation of VXLAN
In a VXLAN environment, you want several geographically remote networks to form a single (or multiple) integrated network(s). For this purpose, you need special nodes named **VTEP**.

Suppose you have two networks, A & B, which both are `192.168.1.0/24` networks, but they are geographically not in the same place and not integrated. With VXLAN, you can join `A` and `B` into one network. For this purpose, you need two VTEP nodes: one at the border of A and another one at the border of B. The connection between A and B is established through the internet (this is just an example; other scenarios may be in place). In this example, we have a VTEP node named `VTEP_A` at the border of A and another VTEP node named `VTEP_B` at the border of B. VTEP_A has several network interfaces, some of which face toward internal nodes of network A, and others face toward the internet. Similarly, VTEP_B has several network interfaces, some of which face toward internal nodes of network B, and others face toward the internet.


![Alt text](./readme/vxlan.drawio.svg)

let's explain a simple scenario, suppose `HOST_11` **knows** the **mac address** of `HOST_21` and want to send it a **ping** request:

1. the ICMP packet will be sent from `HOST_11` to `VTEP_A/eth-in-1`
2. `VTEP_A` will check within its mac table for `HOST_21`, so it will realize which network interface it should forward the packet to.
3. before forwarding the packet it will encapsulate it within another packet with outer ethernet, outer ip, outer udp & outer vxlan headers
4. then `VTEP_A` will forward the packet through `VTEP_A/eth-ext-1` network interface toward the internet.
5. the packet will reach `VTEP_B/eth-ext-1` and will be handed over to `VTEP_B`
6. `VTEP_B` will look for `HOST_21` mac address within its mac table to find which network interface it should forward the packet to.
7. `VTEP_B` will decapsulate the packet so the outer ethernet, outer ip, outer udp & outer vxlan headers will be removed
8.  `VTEP_B` will forward the original decpasulated packet to the `HOST-21` toward `eth-in-1`


## vxlan building blocks using eBPF

to implement a VTEP we need to perform several functionalities:
1. packet `redirection`
2. packet `encapsulation`/`decapsulation`
4. packet `cloning` --> in case we need packet flooding ---> unknown unicast flooding
5. `mac address learning`



### packet redirection

in below picture a network packet reaches to an `internal` NIC of VTEP_A:

1. a packet reaches an internal network interface `eth-in-1` of `VTEP_A`
2. it will be handed over to the `XDP` program that we have already attached to this NIC
3. in the XDP program, it'll check a global eBPF map named `MAC TABLE`. it'll check if it contains any entry for the destination mac address we're trying to send the packet to. suppose we have an entry in the mac table. suppose the in the entry it has stated `eth-ext-1` as forwarding NIC
4. in my eBPF program it'll perform packet redirection to `eth-ext-1` NIC.
5. packet will be sent out from `eth-ext-1` network interface

![Alt text](./readme/inside-vtep.drawio.svg)

in below picture a network packet reaches to an `external` NIC of VTEP_A:

- it is similar to previous scenario, but in reverse ( external network to internal + packet decapsulation at 4)

![Alt text](./readme/outside-vtep.drawio.svg)


the packet redirection in XDP programs can be done using `bpf_redirect()` helper function

### packet encapsulation/decapsulation
suppose `HOST_11` from network A wants to send a packet to `HOST_21` in network B, this is the path it must go through: 

```
HOST_11 --> VTEP_A --> Internet --> VTEP_B --> HOST_21
```

when the packet wants to get out from VTEP_A toward VTEP_B through the **internet**, it must be **`encapsulated`** within another network packet. in an XDP program you can acheive it using `bpf_xdp_adjust_head()` helper function. it will add some headroom to the start of the packet, so one can add extra headers like outer ethernet, outer ip, outer udp & outer vxlan headers. also the same `bpf_xdp_adjust_head()` can be used to shorten the packet length and strip off the outer headers for the purpose of decapsulation when the packet is received by VTEP_B.


![Alt text](./readme/vxlan_headers.jpg)


### packet cloning

suppose `HOST_11` want to ping `HOST_21` (192.168.1.21), but it doesn't know the mac address of it, in this case the OS (windows/linux/mac/...) of the HOST_11, will first send a broadcast ARP request to the network to ask who owns the 192.168.1.21 ip address, and what is the MAC address of the owner. in this case the VTEP_A or even VTEP_B, may have to clone this broadcast ARP request to multiple network interfaces and forward it through all of them. **in eBPF XDP program, one cannot do packet cloning** and **you can only do packet cloning in eBPF TC programs**, using `bpf_clone_redirect()` function.

### mac address learning
whenever a packet reaches a network interface with an XDP program attached to it, by looking at the source MAC address of the packet or inner packet ( in case the packet is encapsulated ) we can perform mac address learning. this can be done easily in XDP programs attached on each internal or external NIC.


## Types of ebpf programs needed for our VXLAN VTEP

currently we have 4 types of ebpf programs to implement a VXLAN VTEP:

- Internal XDP program  --> implemented in `vxlan_xdp_internal.bpf.c`
- Internal TC program   --> implemented in `vxlan_tc_internal.bpf.c`
- External XDP program  --> implemented in `vxlan_xdp_external.bpf.c`
- External TC program   --> implemented in `vxlan_tc_external.bpf.c`

as I previously mentioned upon each VTEP there are several NICs and some of these NICs are facing toward internal hosts of network and connected to them and some of those NICs are facing toward internet.

upon each internal NIC we attach an `Internal XDP program` and an `Internal TC program`.
upon each external NIC we attach an `External XDP program` and an `External TC program`.

Also as I mentioned previously the `TC` programs are for the sake of packet cloning & it is only used in cases that we want to clone and forward a packet to multiple network interfaces. so when we need to perform unknown unicast flooding to a packet in a XDP program, first we'll perform an XDP_PASS on that packet so this network packet will be passed up to upper layer in the networking stack in linux. TC programs higher than XDP programs in the networking stack of linux kernel. TC programs also they have more capabilities. this more capability means packet cloning. although it comes with the cost of being on slower processing pass. when we handle a packet in the XDP layer we are handling it in the fast path, but when we pass the network packet up in the linux networking stack to be processed by a TC program, we are handling it an the slow pass. so unknown unicast flooding is slower than normal packet redirection happening in lower XDP layer.


![Alt text](./readme/xdp_tc.drawio.svg)



## Packet Forwarding Mechanism

In this project, the packet forwarding mechanism is implemented using both XDP and TC layers of eBPF. The process is as follows:

1. **MAC Address Lookup**: When a packet arrives at the VTEP (VXLAN Tunnel Endpoint), the system first checks the MAC address table.
    - **Entry Found**: If an entry for the destination MAC address is found in the MAC table, the packet is forwarded immediately using the XDP layer. This ensures low-latency forwarding.
    - **Entry Not Found**: If no entry is found for the destination MAC address, the packet is passed from the XDP layer to the TC layer.

2. **Unknown Unicast Flooding**: In the TC layer, the system performs unknown unicast flooding. This is necessary because the XDP layer does not support cloning a packet multiple times and redirecting it to multiple destinations. The TC layer handles this by cloning the packet and sending it to all possible destinations.

3. **Jumbo Frames**: For Jumbo frames (packets larger than 1500 bytes), normal `xdp` cannot be used. Instead, a substitute XDP type named `xdp.frags` is used to handle these larger packets.

This approach leverages the strengths of both XDP and TC layers to achieve efficient and scalable packet forwarding.

## Packet Lifecycle

1. **Origin**: The packet starts from a node within an internal host.
2. **Encapsulation**: When it reaches our eBPF VXLAN VTEP, it gets encapsulated within another packet.
3. **Transmission**: The encapsulated packet is transmitted to a remote eBPF VXLAN VTEP.
4. **Decapsulation**: At the remote VTEP, the packet is decapsulated.
5. **Destination**: The packet reaches its final destination.

## Network Packet Diagram


Before running tests, we need to build an image by executing `./scripts/build_images.sh`.
- **eBPF XDP/TC**: Utilizes eBPF XDP/TC for high-performance packet processing.
- **Unknown Unicast Flooding**: Efficiently handles unknown unicast traffic within the VXLAN.

## Network Packet Encapsulation

Below is a diagram showing the network packet before and after encapsulation with outer Ethernet, outer IP, outer UDP, and outer VXLAN headers:

```
+-------------------+-------------------+-------------------+-------------------+-------------------+
| Outer Ethernet Header | Outer IP Header | Outer UDP Header | Outer VXLAN Header | Original Packet |
+-------------------+-------------------+-------------------+-------------------+-------------------+
```

## Getting Started
To get started with the Wormhole project, follow the instructions below.

## Prerequisites
It is based on devcontainer, so for development, one only needs to install VSCode and Docker.
- Linux kernel 6.5 or newer with eBPF support
- Docker
- VSCode

## Running tests
1. Build the image:
    ```sh
    ./scripts/build_images.sh
    ```
2. Run the tests:
    ```sh
    ./script/vxlan_agent_run_tests.sh
    ```

## Usage
To run the Wormhole VXLAN implementation, use the following command:
```sh
sudo ./wormhole
```

## Contributing
We welcome contributions to the Wormhole project. Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements
Special thanks to the eBPF and Linux kernel communities for their invaluable support and contributions.
## Technologies Used
- **Golang/C**: The primary programming languages used in the project.
- **Cilium eBPF**: Utilized for eBPF program management.
- **bpf2go**: Used for generating Go bindings for eBPF programs.
- **Containerlab**: Employed for automated end-to-end testing.
- **Ginkgo Testing Library**: Used for writing and running tests.
- **Edge Shark**: Utilized for network packet analysis.
## Packet Life Cycle

The life cycle of a packet in the Wormhole VXLAN implementation is as follows:

1. **Originating Node**: The packet originates from an internal host within the network.
2. **Ingress to eBPF VXLAN VTEP**: The packet reaches the eBPF VXLAN Virtual Tunnel Endpoint (VTEP) where it is processed by the eBPF XDP/TC program.
3. **Encapsulation**: The packet is encapsulated with an outer Ethernet header, outer IP header, outer UDP header, and outer VXLAN header.
4. **Transmission**: The encapsulated packet is transmitted over the network to the remote eBPF VXLAN VTEP.
5. **Egress from Remote eBPF VXLAN VTEP**: The remote eBPF VXLAN VTEP receives the encapsulated packet.
6. **Decapsulation**: The outer headers are removed, and the original packet is extracted.
7. **Destination Node**: The decapsulated packet is forwarded to the destination host within the network.

This process ensures efficient and scalable network virtualization using the VXLAN protocol.

### MAC Table Management

Each element in the `mac_table` needs to have a 5-minute TTL (Time To Live). To implement this, we use `bpf_timer` along with an eviction callback. The `bpf_timer` ensures that each entry is automatically removed after the TTL expires, maintaining the efficiency and accuracy of the MAC address table.

### Packet Size Adjustment

In this project, when a packet passes through an internal XDP program on the VTEP and needs to be forwarded to a remote destination, we use the `bpf_xdp_adjust_head` function to increase the headroom. This adjustment is essential for encapsulating the packet with additional headers such as outer Ethernet, IP, UDP, and VXLAN headers.

By increasing the headroom, we ensure there is enough space to insert these headers without fragmenting the packet, maintaining the integrity and performance of the packet forwarding mechanism.

The `bpf_xdp_adjust_head` function is used as follows:

```c
int adjust_head(struct xdp_md *ctx) {
    int headroom = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlanhdr);
    if (bpf_xdp_adjust_head(ctx, -headroom)) {
        return XDP_DROP;
    }
    return XDP_PASS;
}
```

Conversely, when a packet passes through an external XDP program on the VTEP and needs to enter the network, we use the same function to strip off the extra headers and decapsulate the internal packet. This ensures that the packet is correctly processed and forwarded to its final destination within the network.

This code snippet demonstrates how we adjust the headroom to accommodate the additional headers during encapsulation and remove them during decapsulation, ensuring efficient packet processing and forwarding.
