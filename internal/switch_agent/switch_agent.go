package switch_agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/allegro/bigcache/v3"
	ciliumEbpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"
	"os"
	"os/signal"
	"time"
	switchAgentEbpfGen "wormhole/internal/switch_agent/ebpf"
)

// SwitchAgent struct encapsulates all related functions and data
type SwitchAgent struct {
	networkInterfaces                []netlink.Link
	xdpObjects                       switchAgentEbpfGen.SwitchAgentXDPObjects
	tcObjects                        switchAgentEbpfGen.SwitchAgentUnknownUnicastFloodingObjects
	userspaceMacTable                *bigcache.BigCache
	userspaceMacTableReInsertChannel chan switchAgentEbpfGen.SwitchAgentXDPMacAddressIfaceEntry
	attachedLinks                    []*link.Link
}

// NewSwitchAgent initializes and returns a new SwitchAgent instance
func NewSwitchAgent(networkInterfaces []netlink.Link) *SwitchAgent {
	return &SwitchAgent{
		userspaceMacTableReInsertChannel: make(chan switchAgentEbpfGen.SwitchAgentXDPMacAddressIfaceEntry),
		networkInterfaces:                networkInterfaces,
	}
}

// ActivateSwitchAgent is the entry point to start the SwitchAgent
func (sa *SwitchAgent) ActivateSwitchAgent(cCtx *cli.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Fatal("Removing memlock:", err)
	}

	logrus.Print("1")

	// Load the compiled eBPF ELF and load it into the kernel.
	if err := switchAgentEbpfGen.LoadSwitchAgentXDPObjects(&sa.xdpObjects, nil); err != nil {
		logrus.Fatal("Loading XDP eBPF objects:", err)
	}
	defer sa.xdpObjects.Close()

	logrus.Print("2")

	if err := switchAgentEbpfGen.LoadSwitchAgentUnknownUnicastFloodingObjects(&sa.tcObjects, nil); err != nil {
		logrus.Fatal("Loading TC eBPF objects:", err)
	}
	defer sa.tcObjects.Close()

	logrus.Print("size of networkInterfaces ", len(sa.networkInterfaces))

	logrus.Print("3")

	if err := sa.addNetworkInterfacesToUnknownUnicastFloodingMaps(); err != nil {
		return err
	}

	logrus.Print("4")

	evictionCallback := sa.createUserspaceMacTableEvictionCallback()
	sa.userspaceMacTable = sa.createUserspaceMacTable(evictionCallback)

	logrus.Print("5")

	go sa.reInsertIntoUserspaceMacTable()

	logrus.Print("6")

	var err error
	sa.attachedLinks, err = sa.attachToInterfaces()
	defer sa.closeAttachedLinks()
	if err != nil {
		return err
	}

	logrus.Print("7")

	go sa.handleNewDiscoveredEntriesRingBuffer()

	logrus.Print("8")

	return sa.waitForCtrlC()
}

func (sa *SwitchAgent) addNetworkInterfacesToUnknownUnicastFloodingMaps() error {

	logrus.Print("3.1")
	err := sa.tcObjects.InterfacesArrayLength.Put(uint32(0), uint32(len(sa.networkInterfaces)))
	if err != nil {
		logrus.Fatalf("something bad happened %s", err)
	}

	logrus.Print("3.2")

	for i, networkInterface := range sa.networkInterfaces {
		logrus.Print("3.3_element")
		err = sa.tcObjects.InterfacesArray.Put(uint32(i), uint32(networkInterface.Attrs().Index))
		if err != nil {
			return err
		}
	}

	logrus.Print("3.4")
	return nil
}

func (sa *SwitchAgent) createUserspaceMacTable(onRemove func(string, []byte)) *bigcache.BigCache {
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

func (sa *SwitchAgent) createUserspaceMacTableEvictionCallback() func(string, []byte) {
	return func(key string, entry []byte) {
		logrus.Print("Eviction1")
		macKey := ConvertStringToMac(key)
		ifaceIndexInKernel := switchAgentEbpfGen.SwitchAgentXDPIfaceIndex{}
		err := sa.xdpObjects.MacTable.Lookup(&macKey, &ifaceIndexInKernel)
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
			// we will realize that this Mac address have been visible to the switch
			// in tha last 5 minutes, so we will re-insert the key/value for that mac
			// address again in the userspace table, with the latest value obtained
			// from the kernel space mac table.

			logrus.Print("Eviction.TryToReinsert")
			sa.userspaceMacTableReInsertChannel <- switchAgentEbpfGen.SwitchAgentXDPMacAddressIfaceEntry{
				Mac:   macKey,
				Iface: ifaceIndexInKernel,
			}
		} else {
			logrus.Printf("Eviction.Delete, for mac: %s", key)
			err := sa.xdpObjects.MacTable.Delete(macKey)
			if err != nil {
				logrus.Fatalf("Error In Deleting %s", err)
			}
		}
		logrus.Print("Eviction.finish")
	}
}

func (sa *SwitchAgent) reInsertIntoUserspaceMacTable() {
	for entry := range sa.userspaceMacTableReInsertChannel {
		logrus.Print("ReInsert.1")
		key := ConvertMacToString(entry.Mac)
		value, _ := EncodeIfaceIndex(entry.Iface)
		logrus.Print("ReInsert.2")
		err := sa.userspaceMacTable.Set(key, value)
		if err != nil {
			logrus.Fatalln("cannot reinsert evicted into userspaceMacTable")
		}
		logrus.Print("ReInsert.3")
	}
}

func (sa *SwitchAgent) attachToInterfaces() ([]*link.Link, error) {
	var attachedLinks []*link.Link

	logrus.Print("6.1")

	for _, iface := range sa.networkInterfaces {
		var err error

		logrus.Print("6.2.element")

		// Attach switchAgentXdp to the network interface.

		attachedXdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   sa.xdpObjects.SwitchAgentXdp,
			Interface: iface.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})

		if err != nil {
			logrus.Fatal("Attaching XDP:", err)
			return attachedLinks, err
		}

		// attach switchAgentUnknownUnicastFlooding to the network interface

		attachedTcLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Attrs().Index,
			Program:   sa.tcObjects.SwitchAgentUnknownUnicastFlooding,
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

func (sa *SwitchAgent) handleNewDiscoveredEntriesRingBuffer() {
	for {
		logrus.Print("HandleNewDiscoveredEntries.1")

		rd, err := ringbuf.NewReader(sa.xdpObjects.NewDiscoveredEntriesRb)
		if err != nil {
			logrus.Fatalf("opening ringbuf reader: %s", err)
		}
		defer rd.Close()

		logrus.Print("HandleNewDiscoveredEntries.2")
		var entry switchAgentEbpfGen.SwitchAgentXDPMacAddressIfaceEntry
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
		sa.userspaceMacTable.Set(key, value)
		logrus.Print("HandleNewDiscoveredEntries.6")
	}
}

func (sa *SwitchAgent) closeAttachedLinks() {
	for _, l := range sa.attachedLinks {
		(*l).Close()
	}
}

func (sa *SwitchAgent) waitForCtrlC() error {
	// Periodically print user mac table
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			logrus.Printf("userspace mac table size %d", sa.userspaceMacTable.Len())
			var (
				key   switchAgentEbpfGen.SwitchAgentXDPMacAddress
				value switchAgentEbpfGen.SwitchAgentXDPIfaceIndex
			)

			for i := 0; sa.xdpObjects.MacTable.Iterate().Next(&key, &value) && i < 3; i++ {
				logrus.Printf("item in kernelspace MacTable, key %s", ConvertMacToString(key))
			}
		case <-stop:
			logrus.Print("Received signal, exiting..")
			return nil
		}
	}
}
