package vxlan_agent

import (
	"encoding/binary"
	"net"
	"os"
	"os/signal"
	"time"
	vxlanAgentEbpfGen "wormhole/internal/vxlan_agent/ebpf"

	ciliumEbpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mostlygeek/arp"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// VxlanAgent struct encapsulates all related functions and data
type VxlanAgent struct {
	internalNetworkInterfaces   []netlink.Link
	externalNetworkInterfaces   []netlink.Link
	neighbourBorderIps          []string
	borderIps                   []uint32
	borderIpToExternalRouteInfo map[uint32]vxlanAgentEbpfGen.VxlanAgentXDPExternalRouteInfo
	xdpObjects                  vxlanAgentEbpfGen.VxlanAgentXDPObjects
	tcObjects                   vxlanAgentEbpfGen.VxlanAgentUnknownUnicastFloodingObjects
	attachedLinks               []*link.Link
}

// NewVxlanAgent initializes and returns a new VxlanAgent instance
func NewVxlanAgent(internalNetworkInterfaces []netlink.Link, externalNetworkInterfaces []netlink.Link, neighborBorderIps []string) *VxlanAgent {
	return &VxlanAgent{
		internalNetworkInterfaces: internalNetworkInterfaces,
		externalNetworkInterfaces: externalNetworkInterfaces,
		neighbourBorderIps:        neighborBorderIps,
	}
}

// ActivateVxlanAgent is the entry point to start the VxlanAgent
func (vxlanAgent *VxlanAgent) ActivateVxlanAgent() error {

	logrus.Print("0. check if we can remove memlock")
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Error("Error removing memlock:", err)
		return err
	}

	logrus.Print("1. find neighbor forwarding mac table")

	if err := vxlanAgent.initExternalRouteInfos(); err != nil {
		logrus.Error("Error finding forwarding macs for neighbor ips using traceroute:", err)
		return err
	}

	// Load the compiled XDP eBPF ELF into the kernel.
	// the xdp program would need to be loaded only once on the system.
	// the tc program also needs to be loaded only once on the system.
	// later we need to attach xdp and tc to all relevant network interfaces.
	logrus.Print("2. load XDP eBPF program")
	if err := vxlanAgentEbpfGen.LoadVxlanAgentXDPObjects(&vxlanAgent.xdpObjects, nil); err != nil {
		logrus.Error("Error loading XDP eBPF program:", err)
		return err
	}
	defer vxlanAgent.xdpObjects.Close()

	logrus.Print("2.1. load TC eBPF program")
	if err := vxlanAgentEbpfGen.LoadVxlanAgentUnknownUnicastFloodingObjects(&vxlanAgent.tcObjects, nil); err != nil {
		logrus.Error("Error loading TC eBPF program:", err)
		return err
	}
	defer vxlanAgent.tcObjects.Close()

	// initialize maps needed by vxlan agent xdp program
	logrus.Print("3. initialize xdp maps")
	if err := vxlanAgent.initVxlanAgentXdpMaps(); err != nil {
		logrus.Error("Error initializing xdp maps:", err)
		return err
	}

	logrus.Print("size of internalNetworkInterfaces ", len(vxlanAgent.internalNetworkInterfaces))

	// initialize maps needed by vxlan agent unknown unicast flooding program
	logrus.Print("4. add network interfaces to unknown unicast flooding maps")
	if err := vxlanAgent.initVxlanAgentUnknownUnicastFloodingMaps(); err != nil {
		logrus.Error("Error initializing unknown unicast flooding maps:", err)
		return err
	}

	// Attach the loaded XDP ebpf program to the network interfaces.
	logrus.Print("5. attach vxlan agent XDP & Unknown Unicast Flooding TC program to interfaces")
	var err error
	vxlanAgent.attachedLinks, err = vxlanAgent.attachVxlanAgentXdpAndTcToAllInterfaces()
	defer vxlanAgent.closeAttachedLinks()
	if err != nil {
		logrus.Error("Error attaching vxlan agent XDP & Unknown Unicast Flooding TC program to interfaces:", err)
		return err
	}

	logrus.Print("6. wait for ctrl+c to stop")
	return vxlanAgent.waitForCtrlC()
}

func (vxlanAgent *VxlanAgent) initExternalRouteInfos() error {

	vxlanAgent.borderIpToExternalRouteInfo = make(map[uint32]vxlanAgentEbpfGen.VxlanAgentXDPExternalRouteInfo)

	for _, borderIp := range vxlanAgent.neighbourBorderIps {
		vxlanAgent.borderIps = append(vxlanAgent.borderIps, binary.BigEndian.Uint32(net.ParseIP(borderIp).To4()))
	}

	for _, neighborBorderIp := range vxlanAgent.neighbourBorderIps {

		dst := net.ParseIP(neighborBorderIp).To4()

		routes, err := netlink.RouteGet(dst)
		if err != nil {
			logrus.Errorf("Failed to get route: %v", err)
			return err
		}

		logrus.Printf("Route to %s: %+v\n", neighborBorderIp, routes[0])
		if routes[0].Gw != nil {
			logrus.Printf("Gateway: %s Mac: %s\n", routes[0].Gw.String(), arp.Search(routes[0].Gw.String()))
		}

		if routes[0].LinkIndex != 0 {
			l, err := netlink.LinkByIndex(routes[0].LinkIndex)
			if err != nil {
				logrus.Errorf("Failed to get link by index: %v", err)
				return err
			}
			logrus.Printf("Interface: %s\n", l.Attrs().Name)
			vxlanAgent.borderIpToExternalRouteInfo[binary.BigEndian.Uint32(dst)] = vxlanAgentEbpfGen.VxlanAgentXDPExternalRouteInfo{
				ExternalIfaceIndex:      uint32(l.Attrs().Index),
				ExternalIfaceMac:        ConvertMacBytesToMac(l.Attrs().HardwareAddr),
				ExternalIfaceNextHopMac: ConvertStringToMac(arp.Search(routes[0].Gw.String())),
				ExternalIfaceIp:         vxlanAgentEbpfGen.VxlanAgentXDPInAddr{S_addr: binary.BigEndian.Uint32(net.ParseIP(neighborBorderIp).To4())},
			}
		}

	}

	return nil
}

func (vxlanAgent *VxlanAgent) initVxlanAgentXdpMaps() error {

	for _, internalNetworkInterface := range vxlanAgent.internalNetworkInterfaces {
		err := vxlanAgent.xdpObjects.IfindexIsInternalMap.Put(uint32(internalNetworkInterface.Attrs().Index), uint32(1))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	for _, externalNetworkInterface := range vxlanAgent.externalNetworkInterfaces {
		err := vxlanAgent.xdpObjects.IfindexIsInternalMap.Put(uint32(externalNetworkInterface.Attrs().Index), uint32(0))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	for borderIp, externalRouteInfo := range vxlanAgent.borderIpToExternalRouteInfo {
		err := vxlanAgent.xdpObjects.BorderIpToRouteInfoMap.Put(borderIp, externalRouteInfo)
		if err != nil {
			logrus.Error("Error putting value in BorderIpToRouteInfoMap:", err)
			return err
		}
	}

	return nil
}

func (vxlanAgent *VxlanAgent) initVxlanAgentUnknownUnicastFloodingMaps() error {

	for borderIp, externalRouteInfo := range vxlanAgent.borderIpToExternalRouteInfo {
		err := vxlanAgent.xdpObjects.BorderIpToRouteInfoMap.Put(borderIp, externalRouteInfo)
		if err != nil {
			logrus.Error("Error putting value in BorderIpToRouteInfoMap:", err)
			return err
		}
	}

	err := vxlanAgent.tcObjects.InternalIfindexesArrayLength.Put(uint32(0), uint32(len(vxlanAgent.internalNetworkInterfaces)))
	if err != nil {
		logrus.Error("Error putting value in InternalIfindexesArrayLength:", err)
		return err
	}

	for i, networkInterface := range vxlanAgent.internalNetworkInterfaces {
		err = vxlanAgent.tcObjects.InternalIfindexesArray.Put(uint32(i), uint32(networkInterface.Attrs().Index))
		if err != nil {
			logrus.Error("Error putting value in InternalIfindexesArray:", err)
			return err
		}
	}

	err = vxlanAgent.tcObjects.RemoteBorderIpsArrayLength.Put(uint32(0), uint32(len(vxlanAgent.borderIps)))
	if err != nil {
		logrus.Error("Error putting value in RemoteBorderIpsArrayLength:", err)
		return err
	}

	for i, borderIp := range vxlanAgent.borderIps {
		err := vxlanAgent.tcObjects.RemoteBorderIpsArray.Put(uint32(i), borderIp)
		if err != nil {
			logrus.Error("Error putting value in RemoteBorderIpsArray:", err)
			return err
		}
	}

	for _, internalNetworkInterface := range vxlanAgent.internalNetworkInterfaces {
		err := vxlanAgent.tcObjects.IfindexIsInternalMap.Put(uint32(internalNetworkInterface.Attrs().Index), uint32(1))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	for _, externalNetworkInterface := range vxlanAgent.externalNetworkInterfaces {
		err := vxlanAgent.tcObjects.IfindexIsInternalMap.Put(uint32(externalNetworkInterface.Attrs().Index), uint32(0))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	return nil
}

func (vxlanAgent *VxlanAgent) attachVxlanAgentXdpAndTcToAllInterfaces() ([]*link.Link, error) {
	var attachedLinks []*link.Link

	logrus.Print("5.1")

	// Combine internal and external interfaces

	for _, iface := range append(vxlanAgent.internalNetworkInterfaces, vxlanAgent.externalNetworkInterfaces...) {
		var err error

		logrus.Print("5.2.element")

		// Attach VxlanAgentXdp to the network interface.
		attachedXdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   vxlanAgent.xdpObjects.VxlanAgentXdp,
			Interface: iface.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})

		if err != nil {
			logrus.Error("Attaching XDP:", err)
			return attachedLinks, err
		}

		// attach VxlanAgentUnknownUnicastFlooding to the network interface
		attachedTcLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Attrs().Index,
			Program:   vxlanAgent.tcObjects.VxlanAgentUnknownUnicastFlooding,
			Attach:    ciliumEbpf.AttachTCXIngress,
			Anchor:    link.Tail(),
		})

		if err != nil {
			logrus.Error("Attaching TCX:", err)
			return attachedLinks, err
		}

		attachedLinks = append(attachedLinks, &attachedXdpLink, &attachedTcLink)
	}

	return attachedLinks, nil
}

func (vxlanAgent *VxlanAgent) closeAttachedLinks() {
	for _, l := range vxlanAgent.attachedLinks {
		(*l).Close()
	}
}

func (vxlanAgent *VxlanAgent) waitForCtrlC() error {
	// Periodically print user mac table
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			// logrus.Printf("userspace mac table size %d", vxlanAgent.xdpObjects.BorderIpToRouteInfoMap.Len())
			var (
				key   vxlanAgentEbpfGen.VxlanAgentXDPMacAddress
				value vxlanAgentEbpfGen.VxlanAgentXDPMacTableEntry
			)

			for i := 0; vxlanAgent.xdpObjects.MacTable.Iterate().Next(&key, &value) && i < 3; i++ {
				logrus.Printf("item in kernelspace MacTable, key %s", ConvertMacToString(key))
			}
		case <-stop:
			logrus.Print("Received signal, exiting..")
			return nil
		}
	}
}
