package main

import (
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"wormhole/cmd/test_agent"
)

func main() {
	lis, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatalf("Failed to listen on port 9000: %v", err)
	}

	s := test_agent.Server{}

	grpcServer := grpc.NewServer()

	test_agent.RegisterChatServiceServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve grpc server over port 9000: %v", err)
	}
}
