package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func main() {
	caCert, _ := os.ReadFile("certs/ca.crt")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	clientCert, _ := tls.LoadX509KeyPair("certs/agent.crt", "certs/agent.key")

	tlsConfig := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
	}

	conn, _ := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	defer conn.Close()
	client := pb.NewSentinelClient(conn)

	// 1. 注册拿 token
	regResp, err := client.Register(context.Background(), &pb.RegisterRequest{
		AgentId:       "test-agent-star",
		Hostname:      "test-host",
		IpAddress:     "127.0.0.1",
		AgentVersion:  "1.0.0",
	})
	if err != nil {
		log.Fatalf("Register 失败: %v", err)
	}
	token := regResp.AgentToken
	fmt.Printf("✅ 注册成功，token=%s\n", token[:8]+"...")

	// 2. 带 token 调用 ReportMutation
	ctx := metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
	resp, err := client.ReportMutation(ctx, &pb.MutationTrigger{
		AgentId:     "test-agent-star",
		Pid:         12345,
		TriggerType: "sensitive_file",
		Detail:      "/etc/shadow",
		Timestamp:   time.Now().Unix(),
	})
	if err != nil {
		log.Fatalf("ReportMutation 失败: %v", err)
	}
	fmt.Printf("✅ ReportMutation 成功: correlation_id=%s\n", resp.Message)
}
