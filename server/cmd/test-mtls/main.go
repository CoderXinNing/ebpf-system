package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/CoderXinNing/ebpf-system/internal/brand"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: test-mtls <cert-dir>")
		os.Exit(1)
	}
	certDir := os.Args[1]

	// 1. 加载 CA
	caCert, err := os.ReadFile(certDir + "/ca.crt")
	if err != nil {
		fmt.Println("❌ 读取 CA 失败:", err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		fmt.Println("❌ 解析 CA 失败")
		os.Exit(1)
	}

	// 2. 加载客户端证书
	clientCert, err := tls.LoadX509KeyPair(certDir+"/agent.crt", certDir+"/agent.key")
	if err != nil {
		fmt.Println("❌ 加载客户端证书失败:", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}

	// 3. 建立 gRPC 连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "localhost:50051",
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		fmt.Println("❌ 连接失败:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("✅ [L1] mTLS 握手成功（CA 验证通过）")

	// 4. 从证书里读 agent_id（用于业务请求）
	cert := clientCert.Certificate[0]
	parsed, _ := x509.ParseCertificate(cert)
	agentID := ""
	for _, uri := range parsed.URIs {
		if uri.Scheme == "spiffe" && uri.Host == brand.SPIFFEDomain {
			agentID = uri.Path
			agentID = agentID[len("/agent/"):]
		}
	}
	fmt.Println("   证书 SAN URI 中的 agent_id:", agentID)

	// 5. 发起一个认证请求（Heartbeat）
	client := pb.NewSentinelClient(conn)
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer reqCancel()
	reqCtx = metadata.NewOutgoingContext(reqCtx, metadata.Pairs("authorization", "Bearer dummy"))

	resp, err := client.Heartbeat(reqCtx, &pb.HeartbeatRequest{
		AgentId:   agentID,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		fmt.Println("❌ 业务请求失败（可能 L2/L3/L4 拒绝）:", err)
		os.Exit(1)
	}

	fmt.Printf("✅ [L2-L4] 业务请求成功: %+v\n", resp)
}
