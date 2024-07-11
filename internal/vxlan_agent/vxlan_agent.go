package vxlan_agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/Kseleven/traceroute-go"
	"github.com/allegro/bigcache/v3"
	ciliumEbpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mostlygeek/arp"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"os"
	"os/signal"
	"time"
	vxlanAgentEbpfGen "wormhole/internal/vxlan_agent/ebpf"
)

// VxlanAgent struct encapsulates all related functions and data
type VxlanAgent struct {
	internalNetworkInterfaces        []netlink.Link
	externalNetworkInterfaces        []netlink.Link
	neighbourBorderIps               []string
	xdpObjects                       vxlanAgentEbpfGen.VxlanAgentXDPObjects
	tcObjects                        vxlanAgentEbpfGen.VxlanAgentUnknownUnicastFloodingObjects
	userspaceMacTable                *bigcache.BigCache
	userspaceMacTableReInsertChannel chan vxlanAgentEbpfGen.VxlanAgentXDPMacAddressIfaceEntry
	attachedLinks                    []*link.Link
	neighborIpToForwardingMac        map[string]string
}

// NewVxlanAgent initializes and returns a new VxlanAgent instance
func NewVxlanAgent(internalNetworkInterfaces []netlink.Link, externalNetworkInterfaces []netlink.Link, neighborBorderIps []string) *VxlanAgent {
	return &VxlanAgent{
		userspaceMacTableReInsertChannel: make(chan vxlanAgentEbpfGen.VxlanAgentXDPMacAddressIfaceEntry),
		internalNetworkInterfaces:        internalNetworkInterfaces,
		externalNetworkInterfaces:        externalNetworkInterfaces,
		neighbourBorderIps:               neighborBorderIps,
	}
}

// ActivateVxlanAgent is the entry point to start the VxlanAgent
func (vxlanAgent *VxlanAgent) ActivateVxlanAgent() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Fatal("Removing memlock:", err)
	}

	if err := vxlanAgent.findNeighborForwardingMacTable(); err != nil {
		logrus.Fatalf("Failed to find forwarding macs for neighbor ips using traceroute")
	}

	logrus.Print("1")

	// Load the compiled eBPF ELF and load it into the kernel.
	if err := vxlanAgentEbpfGen.LoadVxlanAgentXDPObjects(&vxlanAgent.xdpObjects, nil); err != nil {
		logrus.Fatal("Loading XDP eBPF objects:", err)
	}
	defer vxlanAgent.xdpObjects.Close()

	logrus.Print("2")

	if err := vxlanAgentEbpfGen.LoadVxlanAgentUnknownUnicastFloodingObjects(&vxlanAgent.tcObjects, nil); err != nil {
		logrus.Fatal("Loading TC eBPF objects:", err)
	}
	defer vxlanAgent.tcObjects.Close()

	logrus.Print("size of internalNetworkInterfaces ", len(vxlanAgent.internalNetworkInterfaces))

	logrus.Print("3")

	if err := vxlanAgent.addNetworkInterfacesToUnknownUnicastFloodingMaps(); err != nil {
		return err
	}

	logrus.Print("4")

	evictionCallback := vxlanAgent.createUserspaceMacTableEvictionCallback()
	vxlanAgent.userspaceMacTable = vxlanAgent.createUserspaceMacTable(evictionCallback)

	logrus.Print("5")

	go vxlanAgent.reInsertIntoUserspaceMacTable()

	logrus.Print("6")

	var err error
	vxlanAgent.attachedLinks, err = vxlanAgent.attachToInterfaces()
	defer vxlanAgent.closeAttachedLinks()
	if err != nil {
		return err
	}

	logrus.Print("7")

	go vxlanAgent.handleNewDiscoveredEntriesRingBuffer()

	logrus.Print("8")

	return vxlanAgent.waitForCtrlC()
}

func (vxlanAgent *VxlanAgent) findNeighborForwardingMacTable() error {

	vxlanAgent.neighborIpToForwardingMac = make(map[string]string)

	tracerouteConf := &traceroute.TraceConfig{
		Debug:    true,
		FirstTTL: 1,
		MaxTTL:   1,
		Retry:    0,
		WaitSec:  1,
	}

	for _, neighbourBorderIp := range vxlanAgent.neighbourBorderIps {
		results, err := traceroute.Traceroute(neighbourBorderIp, tracerouteConf)

		if err != nil {
			logrus.Error(err.Error())
			return err
		}

		vxlanAgent.neighborIpToForwardingMac[neighbourBorderIp] = arp.Search(results[0].NextHot)

	}

	return nil
}

func (vxlanAgent *VxlanAgent) addNetworkInterfacesToUnknownUnicastFloodingMaps() error {

	logrus.Print("3.1")
	err := vxlanAgent.tcObjects.InterfacesArrayLength.Put(uint32(0), uint32(len(vxlanAgent.internalNetworkInterfaces)))
	if err != nil {
		logrus.Fatalf("something bad happened %s", err)
	}

	logrus.Print("3.2")

	for i, networkInterface := range vxlanAgent.internalNetworkInterfaces {
		logrus.Print("3.3_element")
		err = vxlanAgent.tcObjects.InterfacesArray.Put(uint32(i), uint32(networkInterface.Attrs().Index))
		if err != nil {
			return err
		}
	}

	logrus.Print("3.4")
	return nil
}

func (vxlanAgent *VxlanAgent) createUserspaceMacTable(onRemove func(string, []byte)) *bigcache.BigCache {
	defaultCacheConfig := bigcache.DefaultConfig(20 * time.Second)
	userspaceMacTable, _ := bigcache.New(
		context.Background(),
		bigcache.Config{
			Shards:             defaultCacheConfig.Shards,
			LifeWindow:         defaultCacheConfig.LifeWindow,
			CleanWindow:        1 * time.Second,
			MaxEntriesInWindow: defaultCacheConfig.MaxEntriesInWindow,
			MaxEntrySize:       defaultCacheConfig.MaxEntrySize,
			StatsEnabled:       defaultCacheConfig.StatsEnabled,
			Verbose:            defaultCacheConfig.Verbose,
			HardMaxCacheSize:   defaultCacheConfig.HardMaxCacheSize,
			OnRemove:           onRemove,
			Hasher:             defaultCacheConfig.Hasher,
		})
	return userspaceMacTable
}

func (vxlanAgent *VxlanAgent) createUserspaceMacTableEvictionCallback() func(string, []byte) {
	return func(key string, entry []byte) {
		logrus.Print("Eviction1")
		macKey := ConvertStringToMac(key)
		ifaceIndexInKernel := vxlanAgentEbpfGen.VxlanAgentXDPIfaceIndex{}
		err := vxlanAgent.xdpObjects.MacTable.Lookup(&macKey, &ifaceIndexInKernel)
		if err != nil {
			logrus.Fatalf("Error parsing value in kernel for mac %s, err: %s", key, err)
			return
		}

		logrus.Printf("Eviction2, %d", ifaceIndexInKernel.InterfaceIndex)

		currentTimeNano := uint64(time.Now().UnixNano())
		logrus.Printf("Eviction.currentTimeNano %d", currentTimeNano)
		timestampInKernelNano := ifaceIndexInKernel.Timestamp // convert timestamp to seconds

		timeDifferenceSeconds := (currentTimeNano - timestampInKernelNano) / 1_000_000_000

		logrus.Printf("Eviction.currentTimeNano %d timestampInKernelNano %d TimeDifference %d, for mac: %s", currentTimeNano, timestampInKernelNano, timeDifferenceSeconds, key)

		if timeDifferenceSeconds < 20 {
			// if upon removal of the key in userspace Mac Table we realized that
			// the kernel space equivalent of that item is _not_ older than 5 minutes
			// we will realize that this Mac address have been visible to the Vxlan
			// in tha last 5 minutes, so we will re-insert the key/value for that mac
			// address again in the userspace table, with the latest value obtained
			// from the kernel space mac table.

			logrus.Print("Eviction.TryToReinsert")
			vxlanAgent.userspaceMacTableReInsertChannel <- vxlanAgentEbpfGen.VxlanAgentXDPMacAddressIfaceEntry{
				Mac:   macKey,
				Iface: ifaceIndexInKernel,
			}
		} else {
			logrus.Printf("Eviction.Delete, for mac: %s", key)
			err := vxlanAgent.xdpObjects.MacTable.Delete(macKey)
			if err != nil {
				logrus.Fatalf("Error In Deleting %s", err)
			}
		}
		logrus.Print("Eviction.finish")
	}
}

func (vxlanAgent *VxlanAgent) reInsertIntoUserspaceMacTable() {
	for entry := range vxlanAgent.userspaceMacTableReInsertChannel {
		logrus.Print("ReInsert.1")
		key := ConvertMacToString(entry.Mac)
		value, _ := EncodeIfaceIndex(entry.Iface)
		logrus.Print("ReInsert.2")
		err := vxlanAgent.userspaceMacTable.Set(key, value)
		if err != nil {
			logrus.Fatalln("cannot reinsert evicted into userspaceMacTable")
		}
		logrus.Print("ReInsert.3")
	}
}

func (vxlanAgent *VxlanAgent) attachToInterfaces() ([]*link.Link, error) {
	var attachedLinks []*link.Link

	logrus.Print("6.1")

	for _, iface := range vxlanAgent.internalNetworkInterfaces {
		var err error

		logrus.Print("6.2.element")

		// Attach VxlanAgentXdp to the network interface.

		attachedXdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   vxlanAgent.xdpObjects.VxlanAgentXdp,
			Interface: iface.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})

		if err != nil {
			logrus.Fatal("Attaching XDP:", err)
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
			logrus.Fatal("Attaching TCX:", err)
			return attachedLinks, err
		}

		attachedLinks = append(attachedLinks, &attachedXdpLink, &attachedTcLink)
	}

	return attachedLinks, nil
}

func (vxlanAgent *VxlanAgent) handleNewDiscoveredEntriesRingBuffer() {
	for {
		logrus.Print("HandleNewDiscoveredEntries.1")

		rd, err := ringbuf.NewReader(vxlanAgent.xdpObjects.NewDiscoveredEntriesRb)
		if err != nil {
			logrus.Fatalf("opening ringbuf reader: %s", err)
		}
		defer rd.Close()

		logrus.Print("HandleNewDiscoveredEntries.2")
		var entry vxlanAgentEbpfGen.VxlanAgentXDPMacAddressIfaceEntry
		record, err := rd.Read()

		logrus.Print("HandleNewDiscoveredEntries.3")

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &entry); err != nil {
			logrus.Fatalf("failed parsing ringbuf entry: %s", err)
			continue
		}

		logrus.Print("HandleNewDiscoveredEntries.4")

		key := ConvertMacToString(entry.Mac)
		value, _ := EncodeIfaceIndex(entry.Iface)

		logrus.Print("HandleNewDiscoveredEntries.5")
		vxlanAgent.userspaceMacTable.Set(key, value)
		logrus.Print("HandleNewDiscoveredEntries.6")
	}
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
			logrus.Printf("userspace mac table size %d", vxlanAgent.userspaceMacTable.Len())
			var (
				key   vxlanAgentEbpfGen.VxlanAgentXDPMacAddress
				value vxlanAgentEbpfGen.VxlanAgentXDPIfaceIndex
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
