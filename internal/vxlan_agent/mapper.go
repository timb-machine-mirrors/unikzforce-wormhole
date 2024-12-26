package vxlan_agent

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	vxlanAgentEbpfGen "wormhole/internal/vxlan_agent/ebpf/gen"

	"github.com/sirupsen/logrus"
)

// Pool to cache Encoder and Decoder instances
var (
	gobPool = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

func ConvertMacToString(mac vxlanAgentEbpfGen.VxlanCommonMacAddress) string {
	return fmt.Sprintf("%02X%02X%02X%02X%02X%02X",
		mac.Addr[0], mac.Addr[1], mac.Addr[2], mac.Addr[3], mac.Addr[4], mac.Addr[5])
}

func ConvertMacBytesToMac(macBytes []byte) vxlanAgentEbpfGen.VxlanCommonMacAddress {
	var mac [6]uint8
	copy(mac[:], macBytes)
	return vxlanAgentEbpfGen.VxlanCommonMacAddress{Addr: mac}
}

func ConvertStringToMac(macStr string) vxlanAgentEbpfGen.VxlanCommonMacAddress {
	hwAddr, err := net.ParseMAC(macStr)
	if err != nil {
		logrus.Fatalln("Error decoding MAC address:", err)
	}

	macBytes := []byte(hwAddr)

	var mac [6]uint8
	copy(mac[:], macBytes)

	return vxlanAgentEbpfGen.VxlanCommonMacAddress{Addr: mac}
}
