package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/allegro/bigcache/v3"
	"sync"
	"time"
)

type MyStruct struct {
	Name string
	Age  int
}

type MacAddress [6]byte

// String returns the string representation of the MAC address
func (mac MacAddress) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// Pool to cache Encoder and Decoder instances
var (
	gobPool = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

func encodeStruct(s interface{}) ([]byte, error) {
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
func decodeStruct(data []byte) (MyStruct, error) {
	// Get a buffer from the pool
	buf := gobPool.Get().(*bytes.Buffer)
	defer gobPool.Put(buf)
	buf.Reset() // Reset buffer before decoding

	// Write data to buffer
	_, err := buf.Write(data)
	if err != nil {
		return MyStruct{}, err
	}

	// Decode the buffer into a struct
	var decodedStruct MyStruct
	decoder := gob.NewDecoder(buf)
	err = decoder.Decode(&decodedStruct)
	if err != nil {
		return MyStruct{}, err
	}
	return decodedStruct, nil
}

func main() {
	mac := MacAddress{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}
	//secondMac := MacAddress{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}

	theChannel := make(chan MyStruct)

	onRemove := func(key string, entry []byte) {
		fmt.Println("SOMETHING HAS BEEN REMOVED")
		theChannel <- MyStruct{"BOB", 50}
	}

	// Configure cache (adjust settings as needed)
	ctx := context.Background()                     // Use context for potential future graceful shutdown
	old := bigcache.DefaultConfig(10 * 1024 * 1024) // 10MB capacity
	config := bigcache.Config{
		Shards:             1024,
		LifeWindow:         3 * time.Second,
		CleanWindow:        1 * time.Second,
		MaxEntriesInWindow: 1000 * 10 * 60,
		MaxEntrySize:       500,
		StatsEnabled:       false,
		Verbose:            true,
		HardMaxCacheSize:   0,
		OnRemove:           onRemove,
		Hasher:             old.Hasher,
	}
	cache, err := bigcache.New(ctx, config)
	if err != nil {
		panic(err)
	}
	defer cache.Close() // Close the cache when done

	// Create a sample struct
	myStruct := MyStruct{"Alice", 30}

	// Encode the struct and set the key-value pair in the cache
	data, err := encodeStruct(myStruct)
	if err != nil {
		panic(err)
	}

	err = cache.Set(mac.String(), data) // Expires in 5 minutes
	if err != nil {
		panic(err)
	}

	go func() {
		for message := range theChannel {
			fmt.Println("Received:", message)

			dataReplaced, err := encodeStruct(message)
			if err != nil {
				panic(err)
			}
			cache.Set(mac.String(), dataReplaced)
			fmt.Println("Replaced")
			//
			//// Retrieve the data later...
			//fmt.Println("getting from map")
			//entry, err := cache.Get(mac.String())
			//if err != nil {
			//	fmt.Println("Entry not found")
			//	return
			//}
			//fmt.Println("fucking problem")
			//
			//// Decode the retrieved data back to MyStruct
			//decodedStruct, err := decodeStruct(entry)
			//if err != nil {
			//	fmt.Println("fucking problem")
			//	panic(err)
			//}
			//
			//fmt.Printf("Retrieved struct: Name: %s, Age: %d\n", decodedStruct.Name, decodedStruct.Age)
		}
	}()

	time.Sleep(10 * time.Second)

	// Retrieve the data later...
	entry, err := cache.Get(mac.String())
	if err != nil {
		if errors.Is(err, bigcache.ErrEntryNotFound) {
			fmt.Println("Entry not found")
		} else {
			panic(err)
		}
		return
	}
	//
	// Decode the retrieved data back to MyStruct
	decodedStruct, err := decodeStruct(entry)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Retrieved struct: Name: %s, Age: %d\n", decodedStruct.Name, decodedStruct.Age)
	fmt.Println("end of world")

}
