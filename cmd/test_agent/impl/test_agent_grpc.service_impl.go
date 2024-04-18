package impl

import (
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/emptypb"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"wormhole/cmd/test_agent/generated"
)

var switchAgentProcess *os.Process

type TestAgentServiceImpl struct {
	generated.UnimplementedTestAgentServiceServer
}

func (s *TestAgentServiceImpl) Ping(ctx context.Context, pingRequest *generated.PingRequest) (*generated.PingResponse, error) {
	log.Printf("Received ping request: %s", pingRequest.IpV4Address)

	pinger, err := probing.NewPinger(pingRequest.IpV4Address)
	if err != nil {
		return &generated.PingResponse{Success: false}, nil
	}

	pinger.Count = 3
	err = pinger.Run()
	if err != nil {
		return &generated.PingResponse{Success: false}, nil
	}

	log.Printf("returning the ping result")

	stats := pinger.Statistics()
	return &generated.PingResponse{Success: (float32(stats.PacketsRecv) / float32(stats.PacketsSent)) > 0.5}, nil
}

func (s *TestAgentServiceImpl) EnableSwitchAgent(ctx context.Context, in *generated.EnableSwitchAgentRequest) (*emptypb.Empty, error) {
	fileName := "/build/switch-agent"

	interfacesCommaSeparated := strings.Join(in.InterfaceNames, ",")

	cmd := exec.Command(fileName, "--interface-names", interfacesCommaSeparated)

	err := cmd.Start()
	if err != nil {
		log.Fatalf("error happened during starting the switch_agent: %s", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *TestAgentServiceImpl) DisableSwitchAgent(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {

	err := switchAgentProcess.Signal(syscall.SIGINT)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
