package vxlan_agent

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"wormhole/internal/vxlan_agent/ebpf"

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

func ConvertMacToString(mac ebpf.VxlanAgentXDPMacAddress) string {
	return fmt.Sprintf("%02X%02X%02X%02X%02X%02X",
		mac.Addr[0], mac.Addr[1], mac.Addr[2], mac.Addr[3], mac.Addr[4], mac.Addr[5])
}

func ConvertMacBytesToMac(macBytes []byte) ebpf.VxlanAgentXDPMacAddress {
	var mac [6]uint8
	copy(mac[:], macBytes)
	return ebpf.VxlanAgentXDPMacAddress{Addr: mac}
}

func ConvertStringToMac(macStr string) ebpf.VxlanAgentXDPMacAddress {
	macBytes, err := hex.DecodeString(macStr)
	if err != nil {
		logrus.Fatalln("Error decoding MAC address:", err)
	}

	var mac [6]uint8
	copy(mac[:], macBytes)

	return ebpf.VxlanAgentXDPMacAddress{Addr: mac}
}
