package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/allegro/bigcache/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
	"wormhole/ebpf/switch_agent"
)

// Pool to cache Encoder and Decoder instances
var (
	gobPool = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

func main() {

	app := &cli.App{
		Name:  "switch_agent",
		Usage: "switch_agent, is the program that will reside in each network and facilitate forwarding packets to other networks and also will report to controller",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "interface-names",
				Value: "",
				Usage: "the name of the network interfaces to attach",
			},
		},
		Action: activateSwitchAgent,
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func activateSwitchAgent(cCtx *cli.Context) error {

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	networkInterfaces := findNetworkInterfaces(cCtx)

	// Load the compiled eBPF ELF and load it into the kernel.
	var xdpObjects switch_agent.SwitchAgentXDPObjects
	if err := switch_agent.LoadSwitchAgentXDPObjects(&xdpObjects, nil); err != nil {
		log.Fatal("Loading XDP eBPF objects:", err)
	}
	defer xdpObjects.Close()

	var tcObjects switch_agent.SwitchAgentUnknownUnicastFloodingObjects
	if err := switch_agent.LoadSwitchAgentUnknownUnicastFloodingObjects(&tcObjects, nil); err != nil {
		log.Fatal("Loading TC ebpf objects:", err)
	}
	defer tcObjects.Close()

	err := addNetworkInterfacesToUnknownUnicastFloodingMaps(tcObjects, networkInterfaces)
	if err != nil {
		return err
	}

	// create userspaceMacTable: Cache<MacAddress, IfaceIndex>
	// attention the in allegro bigcache, each entry has string key and byte[] value
	userspaceMacTableReInsertChannel := make(chan switch_agent.SwitchAgentXDPMacAddressIfaceEntry)
	userspaceMacTableEvictionCallback := createUserspaceMacTableEvictionCallback(xdpObjects.MacTable, userspaceMacTableReInsertChannel)
	userspaceMacTable := createUserspaceMacTable(userspaceMacTableEvictionCallback)

	go reInsertIntoUserspaceMacTable(userspaceMacTableReInsertChannel, userspaceMacTable)

	attachedLinks, err := attachToInterfaces(networkInterfaces, xdpObjects, tcObjects)
	defer closeAttachedLinks(attachedLinks)
	if err != nil {
		return err
	}

	go handleNewDiscoveredEntriesRingBuffer(userspaceMacTable, xdpObjects.NewDiscoveredEntriesRb)

	return waitForCtrlC(xdpObjects)
}

func addNetworkInterfacesToUnknownUnicastFloodingMaps(tcObjects switch_agent.SwitchAgentUnknownUnicastFloodingObjects, networkInterfaces []netlink.Link) error {
	err := tcObjects.InterfacesArrayLength.Put(0, len(networkInterfaces))
	if err != nil {
		return err
	}

	for i, networkInterface := range networkInterfaces {
		err = tcObjects.InterfacesArray.Put(i, networkInterface.Attrs().Index)
		if err != nil {
			return err
		}
	}
	return nil
}

func createUserspaceMacTable(onRemove func(string, []byte)) *bigcache.BigCache {
	defaultCacheConfig := bigcache.DefaultConfig(5 * time.Minute)
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

func createUserspaceMacTableEvictionCallback(kernelspaceMacTable *ebpf.Map, userspaceMacTableReInsertChannel chan switch_agent.SwitchAgentXDPMacAddressIfaceEntry) func(string, []byte) {
	return func(key string, entry []byte) {
		macKey := convertStringToMac(key)
		ifaceIndexInKernel := switch_agent.SwitchAgentXDPIfaceIndex{}
		err := kernelspaceMacTable.Lookup(macKey, ifaceIndexInKernel)
		if err != nil {
			log.Fatalf("Error parsing value in kernel for mac %s, err: %s", key, err)
			return
		}

		currentTimeSeconds := time.Now().Unix()
		timestampSecondsInKernel := int64(ifaceIndexInKernel.Timestamp / 1_000_000_000) // convert timestamp to seconds

		timeDifferenceSeconds := currentTimeSeconds - timestampSecondsInKernel

		if timeDifferenceSeconds < 300 {
			// if upon removal of the key in userspace Mac Table we realized that
			// the kernel space equivalent of that item is _not_ older than 5 minutes
			// we will realize that this Mac address have been visible to the switch
			// in tha last 5 minutes, so we will re-insert the key/value for that mac
			// address again in the userspace table, with the latest value obtained
			// from the kernel space mac table.
			userspaceMacTableReInsertChannel <- switch_agent.SwitchAgentXDPMacAddressIfaceEntry{
				Mac:   macKey,
				Iface: ifaceIndexInKernel,
			}
		} else {
			err := kernelspaceMacTable.Delete(key)
			if err != nil {
				return
			}
		}
	}
}

func reInsertIntoUserspaceMacTable(userspaceMacTableReInsertChannel chan switch_agent.SwitchAgentXDPMacAddressIfaceEntry, userspaceMacTable *bigcache.BigCache) {
	for entry := range userspaceMacTableReInsertChannel {

		key := convertMacToString(entry.Mac)
		value, _ := encodeIfaceIndex(entry.Iface)

		err := userspaceMacTable.Set(key, value)
		if err != nil {
			log.Fatalln("cannot reinsert evicted into userspaceMacTable")
		}
	}
}

func findNetworkInterfaces(cCtx *cli.Context) []netlink.Link {
	cliInterfaceNames := strings.TrimSpace(cCtx.String("interface-names"))
	if cliInterfaceNames == "" {
		log.Fatal("--interface-names should be present and not empty")
	}

	interfaceNames := strings.Fields(cliInterfaceNames)

	var ifaces []netlink.Link

	for _, ifaceName := range interfaceNames {
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			log.Fatalf("Getting interface %s: %s", ifaceName, err)
		}

		ifaces = append(ifaces, iface)
	}
	return ifaces
}

func attachToInterfaces(networkInterfaces []netlink.Link, xdpObjects switch_agent.SwitchAgentXDPObjects, tcObjects switch_agent.SwitchAgentUnknownUnicastFloodingObjects) ([]*link.Link, error) {
	var attachedLinks []*link.Link

	for _, iface := range networkInterfaces {
		var err error

		// Attach switchAgentXdp to the network interface.
		attachedXdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   xdpObjects.SwitchAgentXdp,
			Interface: iface.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})

		if err != nil {
			log.Fatal("Attaching XDP:", err)
			return attachedLinks, err
		}

		// attach switchAgentUnknownUnicastFlooding to the network interface
		attachedTcLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Attrs().Index,
			Program:   tcObjects.SwitchAgentUnknownUnicastFlooding,
			Attach:    ebpf.AttachTCXIngress,
			Anchor:    link.ReplaceProgram(tcObjects.SwitchAgentUnknownUnicastFlooding),
		})

		if err != nil {
			log.Fatal("Attaching TCX:", err)
			return attachedLinks, err
		}

		attachedLinks = append(attachedLinks, &attachedXdpLink, &attachedTcLink)
	}

	return attachedLinks, nil
}

func handleNewDiscoveredEntriesRingBuffer(userspaceMacTable *bigcache.BigCache, newDiscoveredEntriesRb *ebpf.Map) {

	for {
		rd, err := ringbuf.NewReader(newDiscoveredEntriesRb)
		if err != nil {
			log.Fatalf("opening ringbuf reader: %s", err)
		}
		defer rd.Close()

		var entry switch_agent.SwitchAgentXDPMacAddressIfaceEntry
		record, err := rd.Read()

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &entry); err != nil {
			log.Fatalf("failedparsing ringbuf entry: %s", err)
			continue
		}

		key := convertMacToString(entry.Mac)
		value, _ := encodeIfaceIndex(entry.Iface)

		userspaceMacTable.Set(key, value)
	}
}

func closeAttachedLinks(links []*link.Link) {
	for _, l := range links {
		(*l).Close()
	}
}

func convertMacToString(mac switch_agent.SwitchAgentXDPMacAddress) string {
	return fmt.Sprintf("%02X%02X%02X%02X%02X%02X",
		mac.Mac[0], mac.Mac[1], mac.Mac[2], mac.Mac[3], mac.Mac[4], mac.Mac[5])
}

func convertStringToMac(macStr string) switch_agent.SwitchAgentXDPMacAddress {
	macBytes, err := hex.DecodeString(macStr)
	if err != nil {
		log.Fatalln("Error decoding MAC address:", err)
	}

	var mac [6]uint8
	copy(mac[:], macBytes)

	return switch_agent.SwitchAgentXDPMacAddress{Mac: mac}
}

func encodeIfaceIndex(s switch_agent.SwitchAgentXDPIfaceIndex) ([]byte, error) {
	// Get a buffer from the pool
	buf := gobPool.Get().(*bytes.Buffer)
	defer gobPool.Put(buf)
	buf.Reset() // Reset buffer before encoding

	// Encode the struct into the buffer
	encoder := gob.NewEncoder(buf)
	err := encoder.Encode(s)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Function to decode a byte slice into a struct
func decodeMacIfaceEntry(data []byte) (switch_agent.SwitchAgentXDPMacAddressIfaceEntry, error) {
	// Get a buffer from the pool
	buf := gobPool.Get().(*bytes.Buffer)
	defer gobPool.Put(buf)
	buf.Reset() // Reset buffer before decoding

	// Write data to buffer
	_, err := buf.Write(data)
	if err != nil {
		return switch_agent.SwitchAgentXDPMacAddressIfaceEntry{}, err
	}

	// Decode the buffer into a struct
	var decodedStruct switch_agent.SwitchAgentXDPMacAddressIfaceEntry
	decoder := gob.NewDecoder(buf)
	err = decoder.Decode(&decodedStruct)
	if err != nil {
		return switch_agent.SwitchAgentXDPMacAddressIfaceEntry{}, err
	}
	return decodedStruct, nil
}

func waitForCtrlC(objs switch_agent.SwitchAgentXDPObjects) error {
	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.MacTable.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return nil
		}
	}
}
