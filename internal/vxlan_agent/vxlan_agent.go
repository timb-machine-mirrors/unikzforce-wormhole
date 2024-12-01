package vxlan_agent

import (
	"encoding/binary"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"time"
	vxlanAgentEbpfGen "wormhole/internal/vxlan_agent/ebpf"

	ciliumEbpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mostlygeek/arp"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// VxlanAgent struct encapsulates all related functions and data
type VxlanAgent struct {
	internalNetworkInterfaces   []netlink.Link
	externalNetworkInterfaces   []netlink.Link
	neighbourBorderIps          []string
	borderIps                   []uint32
	borderIpToExternalRouteInfo map[uint32]vxlanAgentEbpfGen.VxlanCommonExternalRouteInfo
	xdpExternalObjects          vxlanAgentEbpfGen.VxlanXDPExternalObjects
	xdpInternalObjects          vxlanAgentEbpfGen.VxlanXDPInternalObjects
	tcExternalObjects           vxlanAgentEbpfGen.VxlanTCExternalObjects
	tcInternalObjects           vxlanAgentEbpfGen.VxlanTCInternalObjects
	attachedLinks               []*link.Link
}

type VxlanAgentMetadata struct {
	Hostname [64]byte
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
	pinPath := "/sys/fs/bpf"

	// Ensure the pin path exists and is empty
	if err := vxlanAgent.preparePinPath(pinPath); err != nil {
		logrus.Error("Error preparing pin path:", err)
		return err
	}

	// ---------------------------------------------------------------------------
	logrus.Print("2. load XDP eBPF program")

	if err := vxlanAgent.loadVxlanXdpInternalProgram(); err != nil {
		logrus.Error("Error loading VxlanAgent.XdpInternal", err)
		return err
	}
	defer vxlanAgent.xdpInternalObjects.Close()

	if err := vxlanAgent.loadVxlanXdpExternalProgram(); err != nil {
		logrus.Error("Error loading VxlanAgent.XdpExternal", err)
		return err
	}
	defer vxlanAgent.xdpExternalObjects.Close()

	// -------------------------------------
	logrus.Print("2.1. load TC eBPF program")

	if err := vxlanAgent.loadVxlanTcInternalProgram(); err != nil {
		logrus.Error("Error loading VxlanAgent.UnknownUnicastFlooding(TC)", err)
		return err
	}
	defer vxlanAgent.tcInternalObjects.Close()

	if err := vxlanAgent.loadVxlanTcExternalProgram(); err != nil {
		logrus.Error("Error loading VxlanAgent.UnknownUnicastFlooding(TC)", err)
		return err
	}
	defer vxlanAgent.tcExternalObjects.Close()

	// ---------------------------------------------------------------------------

	// initialize maps needed by vxlan agent xdp program
	logrus.Print("3. initialize xdp maps")
	if err := vxlanAgent.initVxlanXdpMaps(); err != nil {
		logrus.Error("Error initializing xdp maps:", err)
		return err
	}

	logrus.Print("size of internalNetworkInterfaces ", len(vxlanAgent.internalNetworkInterfaces))

	// ---------------------

	// initialize maps needed by vxlan agent unknown unicast flooding program
	logrus.Print("4. add network interfaces to unknown unicast flooding maps")
	if err := vxlanAgent.initVxlanTCMaps(); err != nil {
		logrus.Error("Error initializing unknown unicast flooding maps:", err)
		return err
	}

	// ---------------------------------------------------------------------------

	// Attach the loaded XDP ebpf program to the network interfaces.
	logrus.Print("5. attach vxlan agent XDP & Unknown Unicast Flooding TC program to interfaces")
	var err error
	vxlanAgent.attachedLinks, err = vxlanAgent.attachVxlanXdpAndTcToInterfaces()
	defer vxlanAgent.closeAttachedLinks()
	if err != nil {
		logrus.Error("Error attaching vxlan agent XDP & Unknown Unicast Flooding TC program to interfaces:", err)
		return err
	}

	logrus.Print("6. wait for ctrl+c to stop")
	return vxlanAgent.waitForCtrlC()
}

func (vxlanAgent *VxlanAgent) loadVxlanXdpInternalProgram() error {
	var err error

	xdpSpec, err := vxlanAgentEbpfGen.LoadVxlanXDPInternal()
	if err != nil {
		logrus.Error("Error loading XDP eBPF program:", err)
		return err
	}

	var hostBytes [64]byte
	hostname, err := os.Hostname()
	if err != nil {
		logrus.Println("Error retrieving hostname:", err)
		hostname = "Unnamed"
	}

	copy(hostBytes[:], hostname)

	metadata := VxlanAgentMetadata{
		Hostname: hostBytes,
	}

	xdpSpec.RewriteConstants(map[string]interface{}{
		"vxlan_agent_metadata": metadata,
	})

	err = xdpSpec.LoadAndAssign(&vxlanAgent.xdpInternalObjects, &ciliumEbpf.CollectionOptions{
		// Programs: ciliumEbpf.ProgramOptions{
		// 	LogLevel: ciliumEbpf.LogLevelInstruction, // Set log level to 1 to enable logs
		// 	LogSize:  1024 * 1024,                    // Set log size to 1MB,
		// },
		Maps: ciliumEbpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	})
	if err != nil {
		logrus.Error("Error loading XDP eBPF program:", err)
		return err
	}

	return err
}

func (vxlanAgent *VxlanAgent) loadVxlanXdpExternalProgram() error {
	var err error

	xdpSpec, err := vxlanAgentEbpfGen.LoadVxlanXDPExternal()
	if err != nil {
		logrus.Error("Error loading XDP eBPF program:", err)
		return err
	}

	var hostBytes [64]byte
	hostname, err := os.Hostname()
	if err != nil {
		logrus.Println("Error retrieving hostname:", err)
		hostname = "Unnamed"
	}

	copy(hostBytes[:], hostname)

	metadata := VxlanAgentMetadata{
		Hostname: hostBytes,
	}

	xdpSpec.RewriteConstants(map[string]interface{}{
		"vxlan_agent_metadata": metadata,
	})

	err = xdpSpec.LoadAndAssign(&vxlanAgent.xdpExternalObjects, &ciliumEbpf.CollectionOptions{
		Maps: ciliumEbpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	})
	if err != nil {
		logrus.Error("Error loading XDP eBPF program:", err)
		return err
	}

	return err
}

func (vxlanAgent *VxlanAgent) loadVxlanTcInternalProgram() error {
	var err error

	tcSpec, err := vxlanAgentEbpfGen.LoadVxlanTCInternal()
	if err != nil {
		return err
	}

	var hostBytes [64]byte
	hostname, err := os.Hostname()
	if err != nil {
		logrus.Println("Error retrieving hostname:", err)
		hostname = "Unnamed"
	}

	copy(hostBytes[:], hostname)

	metadata := VxlanAgentMetadata{
		Hostname: hostBytes,
	}

	tcSpec.RewriteConstants(map[string]interface{}{
		"vxlan_agent_metadata": metadata,
	})

	err = tcSpec.LoadAndAssign(&vxlanAgent.tcInternalObjects, &ciliumEbpf.CollectionOptions{
		Maps: ciliumEbpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	})

	if err != nil {
		logrus.Error("Error loading TC eBPF program:", err)
		return err
	}

	return err
}

func (vxlanAgent *VxlanAgent) loadVxlanTcExternalProgram() error {
	var err error

	tcSpec, err := vxlanAgentEbpfGen.LoadVxlanTCExternal()
	if err != nil {
		return err
	}

	var hostBytes [64]byte
	hostname, err := os.Hostname()
	if err != nil {
		logrus.Println("Error retrieving hostname:", err)
		hostname = "Unnamed"
	}

	copy(hostBytes[:], hostname)

	metadata := VxlanAgentMetadata{
		Hostname: hostBytes,
	}

	tcSpec.RewriteConstants(map[string]interface{}{
		"vxlan_agent_metadata": metadata,
	})

	err = tcSpec.LoadAndAssign(&vxlanAgent.tcExternalObjects, &ciliumEbpf.CollectionOptions{
		Maps: ciliumEbpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	})

	if err != nil {
		logrus.Error("Error loading TC eBPF program:", err)
		return err
	}

	return err
}

func (vxlanAgent *VxlanAgent) initExternalRouteInfos() error {

	vxlanAgent.borderIpToExternalRouteInfo = make(map[uint32]vxlanAgentEbpfGen.VxlanCommonExternalRouteInfo)

	for _, borderIp := range vxlanAgent.neighbourBorderIps {
		vxlanAgent.borderIps = append(vxlanAgent.borderIps, binary.BigEndian.Uint32(net.ParseIP(borderIp).To4()))
	}

	for _, neighborBorderIpStr := range vxlanAgent.neighbourBorderIps {

		pinger, err := probing.NewPinger(neighborBorderIpStr)
		if err != nil {
			logrus.Errorf("Failed to create pinger: %v", err)
		}

		pinger.Count = 3
		pinger.Timeout = 2 * time.Second
		err = pinger.Run()
		if err != nil {
			logrus.Errorf("Ping failed: %v", err)
		}

		neighBorderIp := net.ParseIP(neighborBorderIpStr).To4()

		routes, err := netlink.RouteGet(neighBorderIp)
		if err != nil {
			logrus.Errorf("Failed to get route: %v", err)
			return err
		}

		logrus.Printf("Route to %s: %+v\n", neighborBorderIpStr, routes[0])
		if routes[0].Gw != nil {
			logrus.Printf("Gateway: %s Mac: %s\n", routes[0].Gw.String(), arp.Search(routes[0].Gw.String()))
		}

		if routes[0].LinkIndex != 0 {
			var externalNextHopMacStr string

			if routes[0].Gw != nil {
				externalNextHopMacStr = arp.Search(routes[0].Gw.String())
				logrus.Printf("Next Hop mac address using Gateway: %s Mac: %s\n", routes[0].Gw.String(), externalNextHopMacStr)
			} else {
				externalNextHopMacStr = arp.Search(routes[0].Dst.IP.String())
				logrus.Printf("Next Hop mac address using Destination: %s Mac: %s\n", routes[0].Dst.IP.String(), externalNextHopMacStr)
			}

			logrus.Printf("Next Hop mac address: %s", externalNextHopMacStr)

			l, err := netlink.LinkByIndex(routes[0].LinkIndex)
			if err != nil {
				logrus.Errorf("Failed to get link by index: %v", err)
				return err
			}
			logrus.Printf("Interface: %s\n", l.Attrs().Name)
			vxlanAgent.borderIpToExternalRouteInfo[binary.BigEndian.Uint32(neighBorderIp)] = vxlanAgentEbpfGen.VxlanCommonExternalRouteInfo{
				ExternalIfaceIndex:      uint32(l.Attrs().Index),
				ExternalIfaceMac:        ConvertMacBytesToMac(l.Attrs().HardwareAddr),
				ExternalIfaceNextHopMac: ConvertStringToMac(externalNextHopMacStr),
				ExternalIfaceIp:         vxlanAgentEbpfGen.VxlanCommonInAddr{S_addr: binary.BigEndian.Uint32(net.ParseIP(routes[0].Src.String()).To4())},
			}
		}

	}

	return nil
}

func (vxlanAgent *VxlanAgent) initVxlanXdpMaps() error {

	// -----------------------

	for _, internalNetworkInterface := range vxlanAgent.internalNetworkInterfaces {
		err := vxlanAgent.xdpInternalObjects.IfindexIsInternalMap.Put(uint32(internalNetworkInterface.Attrs().Index), uint8(1))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	for _, externalNetworkInterface := range vxlanAgent.externalNetworkInterfaces {
		err := vxlanAgent.xdpInternalObjects.IfindexIsInternalMap.Put(uint32(externalNetworkInterface.Attrs().Index), uint8(0))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	// -----------------------

	for _, internalNetworkInterface := range vxlanAgent.internalNetworkInterfaces {
		err := vxlanAgent.xdpExternalObjects.IfindexIsInternalMap.Put(uint32(internalNetworkInterface.Attrs().Index), uint8(1))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	for _, externalNetworkInterface := range vxlanAgent.externalNetworkInterfaces {
		err := vxlanAgent.xdpExternalObjects.IfindexIsInternalMap.Put(uint32(externalNetworkInterface.Attrs().Index), uint8(0))
		if err != nil {
			logrus.Error("Error putting value in IfindexIsInternalMap:", err)
			return err
		}
	}

	// -----------------------

	for borderIp, externalRouteInfo := range vxlanAgent.borderIpToExternalRouteInfo {
		err := vxlanAgent.xdpInternalObjects.BorderIpToRouteInfoMap.Put(borderIp, externalRouteInfo)
		if err != nil {
			logrus.Error("Error putting value in BorderIpToRouteInfoMap:", err)
			return err
		}
	}

	return nil
}

func (vxlanAgent *VxlanAgent) initVxlanTCMaps() error {

	for borderIp, externalRouteInfo := range vxlanAgent.borderIpToExternalRouteInfo {
		err := vxlanAgent.tcInternalObjects.BorderIpToRouteInfoMap.Put(borderIp, externalRouteInfo)
		if err != nil {
			logrus.Error("Error putting value in BorderIpToRouteInfoMap:", err)
			return err
		}
	}

	// ----------------------

	for i, networkInterface := range vxlanAgent.internalNetworkInterfaces {
		err := vxlanAgent.tcInternalObjects.InternalIfindexesArray.Put(uint32(i), uint32(networkInterface.Attrs().Index))
		if err != nil {
			logrus.Error("Error putting value in InternalIfindexesArray:", err)
			return err
		}
	}

	for i, networkInterface := range vxlanAgent.internalNetworkInterfaces {
		err := vxlanAgent.tcExternalObjects.InternalIfindexesArray.Put(uint32(i), uint32(networkInterface.Attrs().Index))
		if err != nil {
			logrus.Error("Error putting value in InternalIfindexesArray:", err)
			return err
		}
	}

	// ----------------------

	err := vxlanAgent.tcInternalObjects.InternalIfindexesArrayLength.Put(uint32(0), uint32(len(vxlanAgent.internalNetworkInterfaces)))
	if err != nil {
		logrus.Error("Error putting value in InternalIfindexesArrayLength:", err)
		return err
	}

	err = vxlanAgent.tcExternalObjects.InternalIfindexesArrayLength.Put(uint32(0), uint32(len(vxlanAgent.internalNetworkInterfaces)))
	if err != nil {
		logrus.Error("Error putting value in InternalIfindexesArrayLength:", err)
		return err
	}

	// ----------------------

	for i, borderIp := range vxlanAgent.borderIps {
		err := vxlanAgent.tcInternalObjects.RemoteBorderIpsArray.Put(uint32(i), borderIp)
		if err != nil {
			logrus.Error("Error putting value in RemoteBorderIpsArray:", err)
			return err
		}
	}

	// ----------------------

	err = vxlanAgent.tcInternalObjects.RemoteBorderIpsArrayLength.Put(uint32(0), uint32(len(vxlanAgent.borderIps)))
	if err != nil {
		logrus.Error("Error putting value in RemoteBorderIpsArrayLength:", err)
		return err
	}

	return nil
}

func (vxlanAgent *VxlanAgent) attachVxlanXdpAndTcToInterfaces() ([]*link.Link, error) {
	var attachedLinks []*link.Link

	logrus.Print("5.1")

	// Combine internal and external interfaces

	for _, iface := range vxlanAgent.internalNetworkInterfaces {
		var err error

		logrus.Print("5.2.element")

		// Attach VxlanAgentXdp to the network interface.
		attachedXdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   vxlanAgent.xdpInternalObjects.VxlanXdpInternal,
			Interface: iface.Attrs().Index,
			Flags:     link.XDPDriverMode,
		})

		if err != nil {
			logrus.Error("Attaching XDP:", err)
			return attachedLinks, err
		}

		attachedLinks = append(attachedLinks, &attachedXdpLink)

		// attach VxlanAgentUnknownUnicastFlooding to the network interface
		attachedTcLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Attrs().Index,
			Program:   vxlanAgent.tcInternalObjects.VxlanTcInternal,
			Attach:    ciliumEbpf.AttachTCXIngress,
			Anchor:    link.Tail(),
		})

		if err != nil {
			logrus.Error("Attaching TCX:", err)
			return attachedLinks, err
		}

		attachedLinks = append(attachedLinks, &attachedTcLink)
	}

	for _, iface := range vxlanAgent.externalNetworkInterfaces {
		var err error

		logrus.Print("5.2.element")

		// Attach VxlanAgentXdp to the network interface.
		attachedXdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   vxlanAgent.xdpExternalObjects.VxlanXdpExternal,
			Interface: iface.Attrs().Index,
			Flags:     link.XDPDriverMode,
		})

		if err != nil {
			logrus.Error("Attaching XDP:", err)
			return attachedLinks, err
		}

		attachedLinks = append(attachedLinks, &attachedXdpLink)

		// attach VxlanAgentUnknownUnicastFlooding to the network interface
		attachedTcLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Attrs().Index,
			Program:   vxlanAgent.tcExternalObjects.VxlanTcExternal,
			Attach:    ciliumEbpf.AttachTCXIngress,
			Anchor:    link.Tail(),
		})

		if err != nil {
			logrus.Error("Attaching TCX:", err)
			return attachedLinks, err
		}

		attachedLinks = append(attachedLinks, &attachedTcLink)
	}

	return attachedLinks, nil
}

func (vxlanAgent *VxlanAgent) closeAttachedLinks() {

	logrus.Print("closing attached links")
	for _, l := range vxlanAgent.attachedLinks {
		err := (*l).Close()
		if err != nil {
			logrus.Errorf("Error closing link: %v", err)
		}
	}

	err := vxlanAgent.xdpExternalObjects.Close()
	if err != nil {
		logrus.Errorf("Error closing xdp objects: %v", err)
	}
	err = vxlanAgent.tcExternalObjects.Close()
	if err != nil {
		logrus.Errorf("Error closing tc objects: %v", err)
	}
}

func (vxlanAgent *VxlanAgent) waitForCtrlC() error {
	// Periodically print user mac table
	// exit the program when interrupted.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-ticker.C:
			// logrus.Printf("userspace mac table size %d", vxlanAgent.xdpObjects.BorderIpToRouteInfoMap.Len())
			var (
				key   vxlanAgentEbpfGen.VxlanCommonMacAddress
				value vxlanAgentEbpfGen.VxlanCommonMacTableEntry
			)

			for i := 0; vxlanAgent.xdpExternalObjects.MacTable.Iterate().Next(&key, &value) && i < 3; i++ {
				logrus.Printf("item in kernelspace MacTable, key %s", ConvertMacToString(key))
			}
		case <-stop:
			logrus.Print("Received signal, exiting..")
			return nil
		}
	}
}

// Add this new method to VxlanAgent struct
func (vxlanAgent *VxlanAgent) preparePinPath(path string) error {
	// Check if the directory exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create the directory if it doesn't exist
		if err := os.MkdirAll(path, 0755); err != nil {
			logrus.Errorf("failed to create directory %s: %v", path, err)
			return err
		}
		logrus.Infof("Created directory: %s", path)
	} else if err != nil {
		logrus.Errorf("error checking directory %s: %v", path, err)
		return err
	} else {
		// Directory exists, clear its contents
		dir, err := os.Open(path)
		if err != nil {
			logrus.Errorf("failed to open directory %s: %v", path, err)
			return err
		}
		defer dir.Close()

		names, err := dir.Readdirnames(-1)
		if err != nil {
			logrus.Errorf("failed to read directory contents %s: %v", path, err)
			return err
		}

		for _, name := range names {
			err = os.RemoveAll(filepath.Join(path, name))
			if err != nil {
				logrus.Errorf("failed to remove %s: %v", name, err)
				return err
			}
		}
		logrus.Infof("Cleared contents of directory: %s", path)
	}

	return nil
}
