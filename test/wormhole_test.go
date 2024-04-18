package test

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/janog-netcon/netcon-problem-management-subsystem/pkg/containerlab"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"testing"
)

func TestCart(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shopping Cart Suite")
}

var _ = Describe("checking switch_agent", func() {

	clabClient := containerlab.NewContainerLabClient("./clab-topologies/switch.clab.yml")
	ctx := context.Background()

	BeforeEach(func() {

		err := clabClient.Deploy(ctx)
		if err != nil {
			fmt.Println("error happened " + err.Error())
		}
	})

	//AfterEach(func() {
	//	err := clabClient.Destroy(ctx)
	//	if err != nil {
	//		fmt.Println("error happened " + err.Error())
	//	}
	//})

	When("the switch_agents run locally", func() {
		dockerClient, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			panic(err)
		}
		defer dockerClient.Close()

		containers, err := dockerClient.ContainerList(context.Background(), types.ContainerListOptions{All: true})
		if err != nil {
			log.Fatalf("error listing the containers: %s", err)
		}

		var (
			sourceContainer types.Container
			switchContainer types.Container
			destContainer   types.Container
		)

		for _, container := range containers {
			if container.Names[0] == "/clab-switch-src" {
				sourceContainer = container
			} else if container.Names[0] == "/clab-switch-sw" {
				switchContainer = container
			} else if container.Names[0] == "/clab-switch-dst" {
				destContainer = container
			}
		}

		log.Printf("source container id %s", sourceContainer.ID)
		log.Printf("switch container id %s", switchContainer.ID)
		log.Printf("dest container id %s", destContainer.ID)

		//dockerClient.ContainerExecCreate(context.Background(), sourceContainer.ID, types.ExecConfig{
		//	AttachStdout: true,
		//	AttachStderr: true,
		//	Cmd:          []string{"echo", "Command executed at the end"},
		//})

		It("returns a non nil sourceContainer", func() {
			Expect(sourceContainer).NotTo(BeNil())
		})

	})

})
