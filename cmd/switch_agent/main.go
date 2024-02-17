package main

import (
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"
	"log"
	"os"
	"os/signal"
	"time"
	"wormhole/ebpf"
)

func main() {

	app := &cli.App{
		Name:  "switch_agent",
		Usage: "switch_agent, is the program that will reside in each network and facilitate forwarding packets to other networks and also will report to controller",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "if-name",
				Value: "",
				Usage: "the name of the network interface",
			},
			&cli.IntFlag{
				Name:  "if-index",
				Value: -1,
				Usage: "the index of the network interface",
			},
		},
		Action: capturePackets,
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func capturePackets(cCtx *cli.Context) error {

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs ebpf.CounterObjects
	if err := ebpf.LoadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := cCtx.String("if-name")
	ifIndex := cCtx.Int("if-index")

	if ifname == "" && ifIndex == -1 {
		ifname = "eth0"
	}

	var iface netlink.Link
	var err error

	if ifname != "" {
		iface, err = netlink.LinkByName(ifname)
		if err != nil {
			log.Fatalf("Getting interface %d: %s", ifIndex, err)
		}
	} else {
		iface, err = netlink.LinkByIndex(ifIndex)
		if err != nil {
			log.Fatalf("Getting interface %d: %s", ifIndex, err)
		}
	}

	log.Print("Interface index:", iface.Attrs().Index)

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
		return err
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", iface.Attrs().Name)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
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
