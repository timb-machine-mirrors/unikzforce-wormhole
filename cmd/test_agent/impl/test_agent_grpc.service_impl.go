package impl

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"wormhole/cmd/test_agent/generated"

	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/emptypb"
)

var switchAgentProcess *os.Process
var vxlanAgentProcess *os.Process

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

	pinger.Count = int(pingRequest.Count)
	pinger.Timeout = time.Duration(pingRequest.Timeout) * time.Second
	//pinger.Count = 3
	//pinger.Timeout = 2 * time.Second
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
	fileName := "/build/switch_agent"

	interfacesCommaSeparated := strings.Join(in.InterfaceNames, ",")

	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("error obtaining the hostname %v", err)
	}

	cmd := exec.Command(fileName, "--interface-names", interfacesCommaSeparated)

	fmt.Println("cmd", cmd.String())
	log.Errorln("cmd", cmd.String())

	err = cmd.Start()

	switchAgentProcess = cmd.Process

	if err != nil {
		fmt.Printf("error %v", err)
		return &generated.EnableSwitchAgentResponse{
			Resp:     fmt.Sprintf("Error: %v", err),
			Command:  cmd.String(),
			Pid:      int32(cmd.Process.Pid),
			Hostname: hostname,
		}, nil
	}

	return &generated.EnableSwitchAgentResponse{
		Resp:     "Success",
		Command:  cmd.String(),
		Pid:      int32(cmd.Process.Pid),
		Hostname: hostname,
	}, nil
}

func (s *TestAgentServiceImpl) DisableSwitchAgent(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {

	err := switchAgentProcess.Signal(syscall.SIGINT)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *TestAgentServiceImpl) EnableVxlanAgent(ctx context.Context, in *generated.EnableVxlanAgentRequest) (*generated.EnableVxlanAgentResponse, error) {
	fileName := "/build/vxlan_agent"

	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("error obtaining the hostname %v", err)
	}

	// remove /build/vxlan_agent.config.yaml if it exists
	err = os.Remove("/build/vxlan_agent.config.yaml")
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("error removing the file %v", err)
	}

	// create and write the content of ConfigYamlContent to /build/vxlan_agent.config.yaml
	file, err := os.Create("/build/vxlan_agent.config.yaml")
	if err != nil {
		log.Errorf("error creating the file %v", err)
		return nil, err
	}
	defer file.Close()

	_, err = file.WriteString(in.ConfigYamlContent)
	if err != nil {
		log.Errorf("error writing to the file %v", err)
		return nil, err
	}

	cmd := exec.Command(fileName, "--config", "/build/vxlan_agent.config.yaml")

	fmt.Println("cmd", cmd.String())
	log.Errorln("cmd", cmd.String())

	// Start the command
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("error obtaining stdout pipe %v", err)
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		log.Errorf("error starting command %v", err)
		return &generated.EnableVxlanAgentResponse{
			Resp:     fmt.Sprintf("Error: %v", err),
			Command:  cmd.String(),
			Output:   "",
			Pid:      0,
			Hostname: hostname,
		}, nil
	}

	// Create a channel to signal when the timeout is reached
	done := make(chan struct{})
	var output []byte

	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				output = append(output, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second * 3):
	}

	vxlanAgentProcess = cmd.Process

	return &generated.EnableVxlanAgentResponse{
		Resp:     "Success",
		Command:  cmd.String(),
		Output:   string(output),
		Pid:      int32(cmd.Process.Pid),
		Hostname: hostname,
	}, nil
}

func (s *TestAgentServiceImpl) DisableVxlanAgent(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {

	err := vxlanAgentProcess.Signal(syscall.SIGINT)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *TestAgentServiceImpl) EnableDummyXdpAgent(ctx context.Context, in *generated.EnableDummyXdpAgentRequest) (*emptypb.Empty, error) {
	fileName := "/build/dummy_xdp"

	cmd := exec.Command(fileName, "--interface-name", in.InterfaceName)

	fmt.Println("cmd", cmd.String())
	log.Errorln("cmd", cmd.String())

	err := cmd.Start()
	if err != nil {
		fmt.Printf("error %v", err)
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func formatStringArray(arr []string) string {
	if len(arr) == 0 {
		return ""
	}
	return "  - " + strings.Join(arr, "\n  - ") + "\n"
}
