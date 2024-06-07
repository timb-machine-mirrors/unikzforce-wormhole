package main

import (
	"fmt"
	"github.com/Kseleven/traceroute-go"
	"github.com/mostlygeek/arp"
)

func main() {
	conf := &traceroute.TraceConfig{
		Debug:    true,
		FirstTTL: 1,
		MaxTTL:   1,
		Retry:    0,
		WaitSec:  1,
	}

	var destAddr = "1.1.1.1"

	fmt.Printf("traceroute to %s %d hots max\n", destAddr, conf.MaxTTL)
	results, err := traceroute.Traceroute(destAddr, conf)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("%s : %s\n", results[0].NextHot, arp.Search(results[0].NextHot))
}
