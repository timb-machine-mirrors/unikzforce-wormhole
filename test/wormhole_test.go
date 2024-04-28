package test

import (
	"context"
	"fmt"
	"github.com/janog-netcon/netcon-problem-management-subsystem/pkg/containerlab"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"testing"
	"wormhole/cmd/test_agent/generated"
)

func TestCart(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shopping Cart Suite")
}

var _ = Describe("checking switch_agent", func() {

	var sourceClient generated.TestAgentServiceClient
	//var switchClient generated.TestAgentServiceClient
	var destClient generated.TestAgentServiceClient

	clabClient := containerlab.NewContainerLabClient("./clab-topologies/switch.clab.yml")
	ctx := context.Background()

	BeforeEach(func() {
		err := clabClient.Destroy(ctx)
		if err != nil {
		}

		err = clabClient.Deploy(ctx)
		if err != nil {
			fmt.Println("error happened " + err.Error())
		}

		log.Printf("something something")

		sourceConn, err := grpc.NewClient("clab-switch-src:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			GinkgoT().Fatalf("Could not connect: %s", err)
		}
		sourceClient = generated.NewTestAgentServiceClient(sourceConn)
		_, err = sourceClient.WaitUntilReady(ctx, &emptypb.Empty{})
		if err != nil {
			GinkgoT().Fatalf("Failed to wait for source container to become ready: %s", err)
		}

		//switchConn, err := grpc.NewClient("clab-switch-sw:9001", grpc.WithTransportCredentials(insecure.NewCredentials()))
		//if err != nil {
		//	GinkgoT().Fatalf("Could not connect: %s", err)
		//}
		//switchClient = generated.NewTestAgentServiceClient(switchConn)

		destConn, err := grpc.NewClient("clab-switch-dst:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
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
			})
			log.Printf("source ping itself stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form source: %s", err)
			}
			Expect(pingResp.Success).To(BeTrue())

			pingResp, err = sourceClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.2",
			})
			log.Printf("source ping dest stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form source: %s", err)
			}
			Expect(pingResp.Success).To(BeFalse())

			pingResp, err = destClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.2",
			})

			log.Printf("dest ping itself stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form dest: %s", err)
			}
			Expect(pingResp.Success).To(BeTrue())

			pingResp, err = destClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.1",
			})

			log.Printf("dest ping source stats, %d, %d, %d, %f", pingResp.PacketsRecv, pingResp.PacketsSent, pingResp.PacketsRecvDuplicates, pingResp.PacketLoss)

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form dest: %s", err)
			}
			Expect(pingResp.Success).To(BeFalse())
		})
	})

	//When("the switch_agent is running", func() {
	//
	//	It("source and dest should be able to ping each other", func() {
	//
	//		enableResp, err := switchClient.EnableSwitchAgent(ctx, &generated.EnableSwitchAgentRequest{InterfaceNames: []string{"eth1", "eth2"}})
	//		if err != nil {
	//			GinkgoT().Fatalf("error while enabling switch_agent: %v", err)
	//		}
	//
	//		log.Print(enableResp.Resp)
	//
	//		pingResp, err := sourceClient.Ping(ctx, &generated.PingRequest{
	//			IpV4Address: "2.2.2.2",
	//		})
	//
	//		if err != nil {
	//			GinkgoT().Fatalf("error while calling Ping form source: %s", err)
	//		}
	//		Expect(pingResp.Success).To(BeTrue())
	//
	//		pingResp, err = destClient.Ping(ctx, &generated.PingRequest{
	//			IpV4Address: "2.2.2.1",
	//		})
	//
	//		if err != nil {
	//			GinkgoT().Fatalf("error while calling Ping form dest: %s", err)
	//		}
	//		Expect(pingResp.Success).To(BeTrue())
	//	})
	//})

})

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
