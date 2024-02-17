package main

import (
	"context"
	"fmt"
	"github.com/janog-netcon/netcon-problem-management-subsystem/pkg/containerlab"
	"os"
)

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current working directory: %v\n", err)
		return
	}
	fmt.Println("Current working directory:", wd)

	clabclient := containerlab.NewContainerLabClient("./clab-topologies/switch.clab.yml")

	ctx := context.Background()

	err2 := clabclient.Deploy(ctx)
	if err2 != nil {
		fmt.Println("error happened " + err2.Error())
	}
}
