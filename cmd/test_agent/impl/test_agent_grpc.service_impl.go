package impl

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"wormhole/cmd/test_agent/generated"
)

type Server struct {
	generated.UnimplementedTestAgentServiceServer
}

func (s *Server) Ping(ctx context.Context, pingRequest *generated.PingRequest) (*generated.PingResponse, error) {
	log.Printf("Received ping request: %s", pingRequest.IpV4Address)
	return &generated.PingResponse{Success: true}, nil
}
