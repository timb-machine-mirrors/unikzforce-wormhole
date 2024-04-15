package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"wormhole/cmd/test_agent/generated"
)

func main() {
	var conn *grpc.ClientConn
	conn, err := grpc.NewClient(":9000", grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		log.Fatal("Could not connect: %s", err)
	}
	defer conn.Close()

	c := generated.NewTestAgentServiceClient(conn)

	message := generated.PingRequest{
		IpV4Address: "8.8.8.8",
	}

	resp, err := c.Ping(context.Background(), &message)

	if err != nil {
		log.Fatalf("error while calling SayHello: %s", err)
	}

	log.Printf("Response from server: %s", resp.Success)

}
