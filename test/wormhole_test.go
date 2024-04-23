package test

import (
	"context"
	"fmt"
	"github.com/janog-netcon/netcon-problem-management-subsystem/pkg/containerlab"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"testing"
	"time"
	"wormhole/cmd/test_agent/generated"
)

func TestCart(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shopping Cart Suite")
}

var _ = Describe("checking switch_agent", func() {

	var sourceClient generated.TestAgentServiceClient
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

		sourceConn, err := grpc.NewClient("clab-switch-src:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			GinkgoT().Fatalf("Could not connect: %s", err)
		}
		sourceClient = generated.NewTestAgentServiceClient(sourceConn)

		destConn, err := grpc.NewClient("clab-switch-dst:9002", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			GinkgoT().Fatalf("Could not connect: %s", err)
		}
		destClient = generated.NewTestAgentServiceClient(destConn)
	})

	AfterEach(func() {
		err := clabClient.Destroy(ctx)
		if err != nil {
			GinkgoT().Fatalf("error happened " + err.Error())
		}
	})

	When("the switch_agent is not running the ping should not work", func() {

		It("returns a non nil sourceContainer", func() {

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			pingResp, err := sourceClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.2",
			})

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form source: %s", err)
			}

			It("returns a non nil sourceContainer", func() {
				Expect(pingResp.Success).To(BeTrue())
			})

			pingResp, err = destClient.Ping(ctx, &generated.PingRequest{
				IpV4Address: "2.2.2.1",
			})

			if err != nil {
				GinkgoT().Fatalf("error while calling Ping form dest: %s", err)
			}

			Expect(pingResp.Success).To(BeTrue())
		})
	})

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
