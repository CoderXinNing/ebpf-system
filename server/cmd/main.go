package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/alert"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/grpcservice"
	"github.com/CoderXinNing/ebpf-system/server/internal/handler"
	"github.com/CoderXinNing/ebpf-system/server/internal/middleware"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository/psql"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository/sqlite"
	"github.com/CoderXinNing/ebpf-system/server/internal/udp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ServerConfig struct {
	Server struct {
		HTTPPort int    `toml:"http_port"`
		GRPCPort int    `toml:"grpc_port"`
		Token    string `toml:"token"`
	} `toml:"server"`
	Database struct {
		Type     string `toml:"type"` // sqlite / postgres
		Path     string `toml:"path"` // SQLite 路径
		Host     string `toml:"host"`
		Port     int    `toml:"port"`
		User     string `toml:"user"`
		Password string `toml:"password"`
		DBName   string `toml:"dbname"`
	} `toml:"database"`
	TLS struct {
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
		CAFile   string `toml:"ca_file"`
	} `toml:"tls"`
}

func main() {
	cfg := loadConfig("server/configs/server.toml")
	if cfg == nil {
		log.Println("⚠️ 使用默认配置")
		cfg = defaultConfig()
	}

	// 数据库（根据配置选择 PSQL 或 SQLite）
	var psqlDB *psql.PSQL
	var sqliteDB *sqlite.SQLite

	if cfg.Database.Type == "postgres" {
		var err error
		psqlDB, err = psql.New(psql.Config{
			Host:     cfg.Database.Host,
			Port:     cfg.Database.Port,
			User:     cfg.Database.User,
			Password: cfg.Database.Password,
			DBName:   cfg.Database.DBName,
		})
		if err != nil {
			log.Fatalf("❌ PSQL 初始化失败: %v", err)
		}
		defer psqlDB.Close()
		log.Println("✅ 使用 PostgreSQL 数据库")
	} else {
		var err error
		sqliteDB, err = sqlite.New(cfg.Database.Path)
		if err != nil {
			log.Fatalf("❌ SQLite 初始化失败: %v", err)
		}
		defer sqliteDB.Close()
		log.Println("✅ 使用 SQLite 数据库")
	}

	// 认证（PSQL）
	var am *auth.AuthManager
	if psqlDB != nil {
		var err error
		am, err = auth.NewAuthManager(psqlDB.Pool())
		if err != nil {
			log.Fatalf("❌ 认证初始化失败: %v", err)
		}
	}

	// Handler（过渡期：继续用 SQLite Store）
	var h *handler.Handler
	if sqliteDB != nil {
		h = handler.NewHandler(sqliteDB.Store, am, nil)
	} else {
		// PSQL 模式：Handler 层用 repository 接口（过渡期）
		h = handler.NewHandlerWithNilStore(nil, nil)
	}

	agentAuth := middleware.NewAgentAuthInterceptor()

	// gRPC Service
	grpcSvc := grpcservice.NewService(h, agentAuth)

	// TLS
	tlsCert := "certs/server.crt"
	tlsKey := "certs/server.key"
	if cfg.TLS.CertFile != "" {
		tlsCert = cfg.TLS.CertFile
	}
	if cfg.TLS.KeyFile != "" {
		tlsKey = cfg.TLS.KeyFile
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		log.Fatalf("❌ gRPC 监听失败: %v", err)
	}
	// mTLS：加载 CA 证书验证客户端
	caCert, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		log.Fatalf("❌ 读取 CA 证书失败: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("❌ 解析 CA 证书失败")
	}

	serverCert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		log.Fatalf("❌ 加载 TLS 证书失败: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	tlsCreds := credentials.NewTLS(tlsConfig)

	grpcServer := grpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.UnaryInterceptor(agentAuth.UnaryInterceptor),
	)
	pb.RegisterSentinelServer(grpcServer, grpcSvc)
	go func() {
		log.Printf("🛡️  gRPC :%d", cfg.Server.GRPCPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("❌ gRPC 服务失败: %v", err)
		}
	}()

	// HTTP
	gin.SetMode(gin.ReleaseMode)

	// UDP 接收端（XDP 保底通道）
	udpServer := udp.NewUDPServer(9999, func(evt udp.UDPEvent) {
		log.Printf("📡 UDP 事件: %v", evt)
	})
	if udpServer == nil {
		log.Printf("⚠️ UDP 接收端启动失败")
	} else {
		log.Println("✅ UDP 接收端已启动 :9999")
	}

	// 定时清理（PSQL 用自己的清理任务）
	if psqlDB != nil {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		psqlDB.StartCleanupTask(ctx)
	} else if sqliteDB != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				sqliteDB.CleanExpiredLogs()
			}
		}()
	}

	// 告警引擎
	_ = alert.NewEngine("server/configs/rules.toml", func(a alert.Alert) {
		log.Printf("🚨 告警: %s", a.RuleName)
	})
	_ = alert.NewCorrelationEngine("server/configs/correlation.toml")

	// 启动 HTTP
	r := gin.Default()
	r.StaticFile("/install.sh", "./server/static/install.sh")
	r.Static("/bin", "./server/static")
	if h != nil && h.Store != nil {
		h.SetupRoutes(r)
	}

	log.Printf("🌐 HTTP :%d", cfg.Server.HTTPPort)
	if err := r.Run(fmt.Sprintf(":%d", cfg.Server.HTTPPort)); err != nil {
		log.Fatalf("❌ HTTP 服务失败: %v", err)
	}
}

func defaultConfig() *ServerConfig {
	cfg := &ServerConfig{}
	cfg.Server.HTTPPort = 8080
	cfg.Server.GRPCPort = 50051
	cfg.Database.Type = "postgres"
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 5432
	cfg.Database.User = "sentinel"
	cfg.Database.Password = "sentinel_dev_2026"
	cfg.Database.DBName = "sentinel"
	cfg.TLS.CertFile = "certs/server.crt"
	cfg.TLS.KeyFile = "certs/server.key"
	cfg.TLS.CAFile = "certs/ca.crt"
	return cfg
}

func loadConfig(path string) *ServerConfig {
	var cfg ServerConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		log.Printf("⚠️ 配置文件读取失败，使用默认配置: %v", err)
		return nil
	}
	return &cfg
}
