package impl

import (
	"fmt"
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/emptypb"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"wormhole/cmd/test_agent/generated"
)

var switchAgentProcess *os.Process

type TestAgentServiceImpl struct {
	generated.UnimplementedTestAgentServiceServer
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func (s *TestAgentServiceImpl) WaitUntilReady(ctx context.Context, in *emptypb.Empty) (*generated.WaitUntilReadyResponse, error) {
	for {
		if fileExists("/tmp/is_clab_container_ready") {
			break
		} else {
			time.Sleep(1 * time.Second)
		}
	}

	return &generated.WaitUntilReadyResponse{Success: true}, nil
}

func (s *TestAgentServiceImpl) Ping(ctx context.Context, pingRequest *generated.PingRequest) (*generated.PingResponse, error) {
	log.Printf("Received ping request: %s", pingRequest.IpV4Address)

	pinger, err := probing.NewPinger(pingRequest.IpV4Address)
	if err != nil {
		return &generated.PingResponse{Success: false}, nil
	}

	pinger.Count = 3
	pinger.Timeout = 2 * time.Second
	err = pinger.Run()
	if err != nil {
		return &generated.PingResponse{
			Success:               false,
			PacketsRecv:           0,
			PacketsSent:           0,
			PacketsRecvDuplicates: 0,
			PacketLoss:            0,
		}, nil
	}

	log.Printf("returning the ping result")

	stats := pinger.Statistics()
	return &generated.PingResponse{Success: stats.PacketLoss < 100,
		PacketsRecv:           int32(stats.PacketsRecv),
		PacketsSent:           int32(stats.PacketsSent),
		PacketsRecvDuplicates: int32(stats.PacketsRecvDuplicates),
		PacketLoss:            float32(stats.PacketLoss),
	}, nil
}

func (s *TestAgentServiceImpl) EnableSwitchAgent(ctx context.Context, in *generated.EnableSwitchAgentRequest) (*generated.EnableSwitchAgentResponse, error) {
	fileName := "/build/switch-agent"

	interfacesCommaSeparated := strings.Join(in.InterfaceNames, ",")

	cmd := exec.Command(fileName, "--interface-names", interfacesCommaSeparated)

	err := cmd.Start()
	if err != nil {
		log.Fatalf("error happened during starting the switch_agent: %s", err)

		return &generated.EnableSwitchAgentResponse{Resp: fmt.Sprintf("Error: %v", err)}, nil
	}

	return &generated.EnableSwitchAgentResponse{Resp: "Success"}, nil
}

func (s *TestAgentServiceImpl) DisableSwitchAgent(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {

	err := switchAgentProcess.Signal(syscall.SIGINT)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
