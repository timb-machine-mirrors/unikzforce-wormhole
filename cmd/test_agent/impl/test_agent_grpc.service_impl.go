package impl

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"wormhole/cmd/test_agent/generated"
)

type Server struct {
	generated.UnimplementedChatServiceServer
}

func (s *Server) SayHello(ctx context.Context, message *generated.Message) (*generated.Message, error) {
	log.Printf("Received message body from client: %s", message.Body)
	return &generated.Message{Body: "Hello From the serv"}, nil
}
