package switch_agent

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/janog-netcon/netcon-problem-management-subsystem/pkg/containerlab"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"slices"
	"strings"
	"testing"
	"wormhole/cmd/test_agent/generated"
)

func TestCart(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shopping Cart Suite")
}

var _ = AfterSuite(func() {

	clabClient := containerlab.NewContainerLabClient("./clab-topologies/switch.clab.yml")
	ctx := context.Background()

	inspect, err := clabClient.Inspect(ctx)
	if err != nil {
		return
	}

	if len(inspect.Containers) != 0 {
		err := clabClient.Destroy(ctx)
		if err != nil {
			GinkgoT().Fatalf("error happened " + err.Error())
		}
	}
})

var _ = Describe("checking switch_agent", func() {

	var sourceClient generated.TestAgentServiceClient
	var switchClient generated.TestAgentServiceClient
	var destClient generated.TestAgentServiceClient

	clabClient := containerlab.NewContainerLabClient("./clab-topologies/switch.clab.yml")
	ctx := context.Background()

	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		GinkgoT().Fatalf("unable to create docker client %v", err)
	}

	BeforeEach(func() {
		err := clabClient.Destroy(ctx)
		if err != nil {
		}

		err = clabClient.Deploy(ctx)
		if err != nil {
			GinkgoT().Fatalf("error happened %v", err)
		}

		containers, err := dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
		if err != nil {
			fmt.Println("Error listing containers:", err)
			return
		}

		sourceIp, err := findContainerIp(containers, "clab-switch-src")
		if err != nil {
			GinkgoT().Fatalf("Enable to find container ip %v", err)
		}
		sourceConn, err := grpc.NewClient(sourceIp+":9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			GinkgoT().Fatalf("Could not connect: %s", err)
		}
		sourceClient = generated.NewTestAgentServiceClient(sourceConn)
		_, err = sourceClient.WaitUntilReady(ctx, &emptypb.Empty{})
		if err != nil {
			GinkgoT().Fatalf("Failed to wait for source container to become ready: %s", err)
		}

		switchIp, err := findContainerIp(containers, "clab-switch-sw")
		switchConn, err := grpc.NewClient(switchIp+":9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			GinkgoT().Fatalf("Could not connect: %s", err)
		}
		switchClient = generated.NewTestAgentServiceClient(switchConn)
		_, err = switchClient.WaitUntilReady(ctx, &emptypb.Empty{})
		if err != nil {
			GinkgoT().Fatalf("Failed to wait for switch container to become ready: %s", err)
		}

		destIp, err := findContainerIp(containers, "clab-switch-dst")
		destConn, err := grpc.NewClient(destIp+":9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			GinkgoT().Fatalf("Could not connect: %s", err)
		}
		destClient = generated.NewTestAgentServiceClient(destConn)
		_, err = destClient.WaitUntilReady(ctx, &emptypb.Empty{})
		if err != nil {
			GinkgoT().Fatalf("Failed to wait for dest container to become ready: %s", err)
		}
	})

	AfterEach(func() {
		err := clabClient.Destroy(ctx)
		if err != nil {
			GinkgoT().Fatalf("error happened " + err.Error())
		}
	})

	When("the switch_agent is not running", func() {

		It("source & dest should not be able to ping each other", func() {

			pingResp, err := sourceClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.1",
				Count:       1,
				Timeout:     1,
			})
			//log.Printf("source ping itself stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)
			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form source: %s", err)
			}
			Expect(pingResp.Success).To(BeTrue())

			pingResp, err = sourceClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.2",
				Count:       2,
				Timeout:     2,
			})
			//log.Printf("source ping dest stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)
			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form source: %s", err)
			}
			Expect(pingResp.Success).To(BeFalse())

			pingResp, err = destClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.2",
				Count:       1,
				Timeout:     1,
			})
			//log.Printf("dest ping itself stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)
			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form dest: %s", err)
			}
			Expect(pingResp.Success).To(BeTrue())

			pingResp, err = destClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.1",
				Count:       2,
				Timeout:     2,
			})
			//log.Printf("dest ping source stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)
			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form dest: %s", err)
			}
			Expect(pingResp.Success).To(BeFalse())
		})
	})

	When("the switch_agent is running", func() {

		It("source and dest should be able to ping each other", func() {

			enableResp, err := switchClient.EnableSwitchAgent(ctx, &generated.EnableSwitchAgentRequest{InterfaceNames: []string{"eth1", "eth2"}})
			if err != nil {
				GinkgoT().Fatalf("error while enabling switch_agent: %v", err)
			}

			Expect(enableResp.Resp).To(Equal("Success"))

			pingResp, err := sourceClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.2",
				Count:       3,
				Timeout:     2,
			})

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form source: %s", err)
			}
			Expect(pingResp.Success).To(BeTrue())

			pingResp, err = destClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.1",
				Count:       3,
				Timeout:     2,
			})

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form dest: %s", err)
			}
			Expect(pingResp.Success).To(BeTrue())
		})
	})

})

func findContainerIp(containers []types.Container, containerName string) (string, error) {
	sourceIdx := slices.IndexFunc(containers, func(container types.Container) bool {
		return slices.ContainsFunc(container.Names, func(name string) bool {
			return strings.Contains(name, containerName)
		})
	})

	if sourceIdx < 0 {
		return "", fmt.Errorf("IP address not found for container '%s'", containerName)
	}

	for _, value := range containers[sourceIdx].NetworkSettings.Networks {
		return value.IPAddress, nil
	}

	return "", fmt.Errorf("IP address not found for container '%s'", containerName)
}
