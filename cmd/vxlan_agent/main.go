package main

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"
	"os"
	"strings"
	"wormhole/internal/vxlan_agent"
)

func main() {
	app := &cli.App{
		Name:  "vxlan_agent",
		Usage: "vxlan_agent, is the program that will reside in each network and facilitate forwarding packets to other networks and also will report to controller",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "internal-interface-names",
				Value: "",
				Usage: "the name of the internal network interfaces",
			},
			&cli.StringFlag{
				Name:  "external-interface-names",
				Value: "",
				Usage: "the name of the external network interfaces",
			},
			&cli.StringFlag{
				Name:  "neighbour-border-ips",
				Value: "",
				Usage: "IPs of other neighboring vxlan agents",
			},
		},
		Action: ActivateVxlanAgent,
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatalf("error %s", err)
		panic(err)
	}
}

func ActivateVxlanAgent(cCtx *cli.Context) error {
	internalNetworkInterfaces := findNetworkInterfaces(cCtx, "internal-interface-names")
	externalNetworkInterfaces := findNetworkInterfaces(cCtx, "external-interface-names")
	neighbourBorderIps := findNeighbourBorderIps(cCtx)

	vxlanAgent := vxlan_agent.NewVxlanAgent(internalNetworkInterfaces, externalNetworkInterfaces, neighbourBorderIps)

	return vxlanAgent.ActivateVxlanAgent()
}

func findNetworkInterfaces(cCtx *cli.Context, argumentName string) []netlink.Link {
	cliInterfaceNames := strings.TrimSpace(cCtx.String(argumentName))
	if cliInterfaceNames == "" {
		logrus.Fatal("--interface-names should be present and not empty")
	}

	logrus.Println(cliInterfaceNames)

	interfaceNames := strings.Split(cliInterfaceNames, ",")
	logrus.Println(interfaceNames)

	var ifaces []netlink.Link

	for _, ifaceName := range interfaceNames {
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			logrus.Fatalf("Getting interface %s: %s", ifaceName, err)
		}

		ifaces = append(ifaces, iface)
	}
	return ifaces
}

func findNeighbourBorderIps(cCtx *cli.Context) []string {
	cliNeighbourBorderIps := strings.TrimSpace(cCtx.String("neighbour-border-ips"))
	if cliNeighbourBorderIps == "" {
		logrus.Fatal("--neighbour-border-ips should be present and not empty")
	}

	return strings.Split(cliNeighbourBorderIps, ",")
}
