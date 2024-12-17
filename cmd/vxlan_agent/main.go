package main

import (
	"io"
	"os"
	"strconv"
	"strings"
	"wormhole/internal/vxlan_agent"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v3"
)

type VxlanAgentConfig struct {
	Networks []VxlanAgentNetworkConfig `yaml:"networks"`
}

type VxlanAgentNetworkConfig struct {
	VNI                       int      `yaml:"vni"`
	Address                   string   `yaml:"address"`
	InternalNetworkInterfaces []string `yaml:"internal-network-interfaces"`
	ExternalNetworkInterfaces []string `yaml:"external-network-interfaces"`
	BorderIPs                 []string `yaml:"border-ips"`
}

func main() {
	app := &cli.App{
		Name:  "vxlan_agent",
		Usage: "vxlan_agent, is the program that will reside in each network and facilitate forwarding packets to other networks and also will report to controller",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Value: "",
				Usage: "path to vxlan network config file",
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
	networks := extractVxlanNetworks(readVxlanConfigFromFile(cCtx))

	vxlanAgent := vxlan_agent.NewVxlanAgent(networks)

	return vxlanAgent.ActivateVxlanAgent()
}

func readVxlanConfigFromFile(cCtx *cli.Context) VxlanAgentConfig {
	configFilePath := strings.TrimSpace(cCtx.String("config"))

	file, err := os.Open(configFilePath)
	if err != nil {
		logrus.Fatalf("failed to open file: %s", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		logrus.Fatalf("failed to read file: %s", err)
	}

	var config VxlanAgentConfig

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		logrus.Fatalf("failed to convert yaml to struct: %s", err)
	}
	return config
}

func extractVxlanNetworks(config VxlanAgentConfig) []vxlan_agent.VxlanAgentNetwork {
	networks := []vxlan_agent.VxlanAgentNetwork{}

	for _, netConfig := range config.Networks {

		parts := strings.Split(netConfig.Address, "/")
		if len(parts) != 2 {
			logrus.Fatalf("Invalid CIDR format %s", netConfig.Address)
		}

		address := parts[0]

		prefixlen, err := strconv.Atoi(parts[1])
		if err != nil {
			logrus.Fatalf("Error parsing prefix length: %s", err)
		}

		networks = append(networks, vxlan_agent.VxlanAgentNetwork{
			VNI:                       netConfig.VNI,
			Prefix:                    prefixlen,
			Address:                   address,
			InternalNetworkInterfaces: findNetworkInterfaces(netConfig.InternalNetworkInterfaces),
			ExternalNetworkInterfaces: findNetworkInterfaces(netConfig.ExternalNetworkInterfaces),
			BorderIPs:                 netConfig.BorderIPs,
		})
	}
	return networks
}

func findNetworkInterfaces(interfaceNames []string) []netlink.Link {

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
