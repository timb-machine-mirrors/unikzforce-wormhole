package impl

import (
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
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
