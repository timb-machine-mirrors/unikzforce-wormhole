package impl

import (
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/emptypb"
	"os/exec"
	"wormhole/cmd/test_agent/generated"
)

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

	return &emptypb.Empty{}, nil
}

func (s *Server) DisableSwitchAgent(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {

	return &emptypb.Empty{}, nil
}
