package main

import (
	"fmt"
	"net"

	"github.com/mostlygeek/arp"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func main() {
	//conf := &traceroute.TraceConfig{
	//	Debug:    true,
	//	FirstTTL: 1,
	//	MaxTTL:   1,
	//	Retry:    0,
	//	WaitSec:  1,
	//}
	//
	//var destAddr = "1.1.1.1"
	//
	//fmt.Printf("traceroute to %s %d hots max\n", destAddr, conf.MaxTTL)
	//results, err := traceroute.Traceroute(destAddr, conf)
	//if err != nil {
	//	fmt.Println(err.Error())
	//	return
	//}
	//
	//fmt.Printf("%s : %s\n", results[0].NextHot, arp.Search(results[0].NextHot))

	// via the new vay to `ip route get 1.1.1.1`
	destination := "1.1.1.1"
	dst := net.ParseIP(destination)

	routes, err := netlink.RouteGet(dst)
	if err != nil {
		log.Fatalf("Failed to get route: %v", err)
	}

	for _, route := range routes {
		fmt.Printf("Route to %s: %+v\n", destination, route)
		if route.Gw != nil {
			log.Printf("Gateway: %s Mac: %s\n", route.Gw.String(), arp.Search(route.Gw.String()))
		}
		if route.LinkIndex != 0 {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				log.Fatalf("Failed to get link by index: %v", err)
			}
			log.Printf("Interface: %s\n", link.Attrs().Name)
		}
	}
}
