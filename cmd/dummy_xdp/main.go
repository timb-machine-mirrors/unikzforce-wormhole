package main

import (
	"os"
	"strings"
	"wormhole/internal/dummy_xdp"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"
)

func main() {
	app := &cli.App{
		Name:  "dummy_xdp",
		Usage: "dummy_xdp, is just a dummy xdp_pass program that will attach itself on a network interface",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "interface-name",
				Value: "",
				Usage: "the name of the network interface we want to attach to",
			},
		},
		Action: ActivateDummyXdp,
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatalf("error %s", err)
		panic(err)
	}
}

func ActivateDummyXdp(cCtx *cli.Context) error {
	networkInterface := findNetworkInterface(cCtx, "interface-name")

	dummyXdp := dummy_xdp.NewDummyXdp(networkInterface)

	return dummyXdp.ActivateDummyXdp()
}

func findNetworkInterface(cCtx *cli.Context, interfaceName string) netlink.Link {
	cliInterfaceName := strings.TrimSpace(cCtx.String(interfaceName))
	if cliInterfaceName == "" {
		logrus.Fatalf("%s should be present and not empty", interfaceName)
	}

	logrus.Println(cliInterfaceName)

	iface, err := netlink.LinkByName(cliInterfaceName)
	if err != nil {
		logrus.Fatalf("Getting interface %s: %s", cliInterfaceName, err)
	}

	return iface
}
