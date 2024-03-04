package main

import (
	"bytes"
	"context"
	"encoding/gob"
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

import (
	"encoding/binary"
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
				Usage: "the name of the network interface",
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

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs switch_agent.SwitchAgentXDPObjects
	if err := switch_agent.LoadSwitchAgentXDPObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifaces := networkInterfaces(cCtx)

	userMacTable, _ := bigcache.New(context.Background(), bigcache.DefaultConfig(5*time.Minute))

	for _, iface := range ifaces {
		var err error

		// Attach count_packets to the network interface.
		link, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.SwitchAgentXdp,
			Interface: iface.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})

		if err != nil {
			log.Fatal("Attaching XDP:", err)
			return err
		}

		defer link.Close()
	}

	go handleNewDiscoveredEntries(userMacTable, objs.NewDiscoveredEntriesRb)

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

func networkInterfaces(cCtx *cli.Context) []netlink.Link {
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

func handleNewDiscoveredEntries(userMacTable *bigcache.BigCache, newDiscoveredEntriesRb *ebpf.Map) {

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

		key := convertToString(entry.Mac)
		value, _ := encodeStruct(entry.Iface)

		userMacTable.Set(key, value)
	}
}

func convertToString(mac switch_agent.SwitchAgentXDPMacAddress) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		mac.Mac[0], mac.Mac[1], mac.Mac[2], mac.Mac[3], mac.Mac[4], mac.Mac[5])
}

func encodeStruct(s switch_agent.SwitchAgentXDPIfaceIndex) ([]byte, error) {
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

//// Function to decode a byte slice into a struct
//func decodeStruct(data []byte) (MyStruct, error) {
//	// Get a buffer from the pool
//	buf := gobPool.Get().(*bytes.Buffer)
//	defer gobPool.Put(buf)
//	buf.Reset() // Reset buffer before decoding
//
//	// Write data to buffer
//	_, err := buf.Write(data)
//	if err != nil {
//		return MyStruct{}, err
//	}
//
//	// Decode the buffer into a struct
//	var decodedStruct MyStruct
//	decoder := gob.NewDecoder(buf)
//	err = decoder.Decode(&decodedStruct)
//	if err != nil {
//		return MyStruct{}, err
//	}
//	return decodedStruct, nil
//}
