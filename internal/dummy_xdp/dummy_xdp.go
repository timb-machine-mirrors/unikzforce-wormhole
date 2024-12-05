package dummy_xdp

import (
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dummyXdpEbpfGen "wormhole/internal/dummy_xdp/ebpf"
)

type DummyXdp struct {
	networkInterface netlink.Link
	dummyXdpObjects  dummyXdpEbpfGen.DummyXdpObjects
}

func NewDummyXdp(networkInterface netlink.Link) *DummyXdp {
	return &DummyXdp{
		networkInterface: networkInterface,
	}
}

func (dummyXdp *DummyXdp) ActivateDummyXdp() error {
	logrus.Print("0. check if we can remove memlock")
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Error("Error removing memlock:", err)
		return err
	}

	dummyXdpSpec, err := dummyXdpEbpfGen.LoadDummyXdp()
	if err != nil {
		logrus.Error("Error loading dummy XDP skeleton into user memory", err)
		return err
	}

	err = dummyXdpSpec.LoadAndAssign(&dummyXdp.dummyXdpObjects, nil)
	defer dummyXdp.dummyXdpObjects.Close()
	if err != nil {
		logrus.Error("Error loading dummy XDP program into kernel memory", err)
		return err
	}

	attachedXdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   dummyXdp.dummyXdpObjects.DummyXdp,
		Interface: dummyXdp.networkInterface.Attrs().Index,
		Flags:     link.XDPDriverMode,
	})
	defer attachedXdpLink.Close()
	if err != nil {
		logrus.Error("Error attaching dummy XDP program to network interface")
		return err
	}

	return dummyXdp.waitForCtrlC()
}

func (dummyXdp *DummyXdp) waitForCtrlC() error {
	// Periodically print user mac table
	// exit the program when interrupted.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			logrus.Print("Received signal, exiting..")
			return nil
		}
	}
}
