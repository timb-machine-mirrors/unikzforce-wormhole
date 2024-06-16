package switch_agent

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/sirupsen/logrus"
	"sync"
	"wormhole/internal/switch_agent/ebpf"
)

// Pool to cache Encoder and Decoder instances
var (
	gobPool = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

func ConvertMacToString(mac ebpf.SwitchAgentXDPMacAddress) string {
	return fmt.Sprintf("%02X%02X%02X%02X%02X%02X",
		mac.Mac[0], mac.Mac[1], mac.Mac[2], mac.Mac[3], mac.Mac[4], mac.Mac[5])
}

func ConvertStringToMac(macStr string) ebpf.SwitchAgentXDPMacAddress {
	macBytes, err := hex.DecodeString(macStr)
	if err != nil {
		logrus.Fatalln("Error decoding MAC address:", err)
	}

	var mac [6]uint8
	copy(mac[:], macBytes)

	return ebpf.SwitchAgentXDPMacAddress{Mac: mac}
}

func EncodeIfaceIndex(s ebpf.SwitchAgentXDPIfaceIndex) ([]byte, error) {
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
func decodeMacIfaceEntry(data []byte) (ebpf.SwitchAgentXDPMacAddressIfaceEntry, error) {
	// Get a buffer from the pool
	buf := gobPool.Get().(*bytes.Buffer)
	defer gobPool.Put(buf)
	buf.Reset() // Reset buffer before decoding

	// Write data to buffer
	_, err := buf.Write(data)
	if err != nil {
		return ebpf.SwitchAgentXDPMacAddressIfaceEntry{}, err
	}

	// Decode the buffer into a struct
	var decodedStruct ebpf.SwitchAgentXDPMacAddressIfaceEntry
	decoder := gob.NewDecoder(buf)
	err = decoder.Decode(&decodedStruct)
	if err != nil {
		return ebpf.SwitchAgentXDPMacAddressIfaceEntry{}, err
	}
	return decodedStruct, nil
}
