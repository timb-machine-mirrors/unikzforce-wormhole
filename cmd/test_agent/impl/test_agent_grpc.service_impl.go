package impl

import (
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/emptypb"
	"os"
	"os/exec"
	"syscall"
	"wormhole/cmd/test_agent/generated"
)

var switchAgentProcess *os.Process

type Server struct {
	generated.UnimplementedTestAgentServiceServer
}

func (s *Server) Ping(ctx context.Context, pingRequest *generated.PingRequest) (*generated.PingResponse, error) {
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

func (s *Server) EnableSwitchAgent(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {
	fileName := "/switch-build/switch-agent"

	cmd := exec.Command(fileName)

	err := cmd.Start()
	if err != nil {
		log.Fatalf("error happened during starting the switch_agent: %s", err)
	}

	switchAgentProcess = cmd.Process

	return &emptypb.Empty{}, nil
}

func (s *Server) DisableSwitchAgent(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {

	err := switchAgentProcess.Signal(syscall.SIGINT)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
