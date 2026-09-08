package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/alert"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/grpcservice"
	"github.com/CoderXinNing/ebpf-system/server/internal/handler"
	"github.com/CoderXinNing/ebpf-system/server/internal/middleware"
	"github.com/CoderXinNing/ebpf-system/server/internal/model"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository/psql"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository/sqlite"
	"github.com/CoderXinNing/ebpf-system/server/internal/udp"
	"github.com/CoderXinNing/ebpf-system/server/internal/ws"
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
		h = handler.NewHandlerWithNilStore(am, nil)
		if psqlDB != nil {
			h.SetListStarEventsFunc(func(corrID string) ([]map[string]interface{}, error) {
		events, err := psqlDB.ListEventsByCorrelationID(context.Background(), corrID)
		if err != nil {
			return nil, err
		}
		result := make([]map[string]interface{}, 0, len(events))
		for _, evt := range events {
			result = append(result, map[string]interface{}{
				"id":             evt.ID,
				"agent_id":       evt.AgentID,
				"probe_name":     evt.ProbeName,
				"event_type":     evt.EventType,
				"pid":            evt.PID,
				"comm":           evt.Comm,
				"filename":       evt.Filename,
				"details":        evt.Details,
				"correlation_id": evt.CorrelationID,
				"timestamp":      evt.Timestamp.Unix(),
			})
		}
		return result, nil
	})
	h.SetListAlertsFunc(func(limit int) ([]map[string]interface{}, error) {
				alerts, err := psqlDB.ListAlerts(context.Background(), limit)
				if err != nil {
					return nil, err
				}
				result := make([]map[string]interface{}, 0, len(alerts))
				for _, a := range alerts {
					detectedAt := ""
					if a.DetectedAt != nil {
						detectedAt = a.DetectedAt.Format(time.RFC3339)
					}
					result = append(result, map[string]interface{}{
						"id":             a.ID,
						"rule_name":      a.RuleName,
						"severity":       a.Severity,
						"description":    a.Description,
						"agent_id":       a.AgentID,
						"pid":            a.PID,
						"comm":           a.Comm,
						"correlation_id": a.CorrelationID,
						"status":         a.Status,
						"detected_at":    detectedAt,
					})
				}
				return result, nil
			})
			h.SetSaveAgentFunc(func(agent handler.AgentInfo) error {
				return psqlDB.SaveAgent(context.Background(), &model.Agent{
					ID:               agent.ID,
					Hostname:         agent.Hostname,
					IPAddr:           agent.IPAddr,
					Version:          agent.Version,
					CapabilityLevel:  agent.CapabilityLevel,
					ActiveProbes:     agent.ActiveProbes,
					BaselineState:    "learning",
					FirstSeen:        time.Unix(agent.FirstSeen, 0),
					LastSeen:         time.Unix(agent.LastSeen, 0),
					LearningDuration: "1 minute",
				})
			})
			h.SetSaveEventFunc(func(evt handler.ProbeEvent) error {
				return psqlDB.SaveEvent(context.Background(), &model.Event{
					AgentID:    evt.AgentID,
					ProbeName:  evt.ProbeName,
					EventType:  evt.EventType,
					PID:        int32(evt.PID),
					Comm:       evt.Comm,
					Filename:   evt.Filename,
					Details:    evt.Details,
					CorrelationID: evt.CorrelationID,
					SourceChannel: "grpc",
					Timestamp:  time.Unix(evt.Timestamp, 0),
				})
			})
		}
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

	// 告警引擎（保存引用，供事件检查使用）
	alertEngine := alert.NewEngine("server/configs/rules.toml", func(a alert.Alert) {
		log.Printf("🚨 告警: %s corrID=%s", a.RuleName, a.CorrelationID)

		// 保存告警到 PSQL
		if psqlDB != nil {
			detectedAt := a.Time
			log.Printf("📝 保存告警到 PSQL: %s", a.RuleName)
			if err := psqlDB.SaveAlert(context.Background(), &model.Alert{
				CorrelationID:  a.CorrelationID,
				RuleName:       a.RuleName,
				Severity:       a.Severity,
				Description:    a.Description,
				AgentID:        a.AgentID,
				PID:            a.PID,
				Comm:           a.Comm,
				Filename:       a.Filename,
				Details:        a.Details,
				Source:         "hard_rule",
				DetectionLevel: "ebpf",
				ActionType:     "detect",
				Status:         "open",
				DetectedAt:     &detectedAt,
			}); err != nil {
				log.Printf("⚠️ 告警落库失败: %v", err)
			} else {
				log.Printf("✅ 告警已落库: %s", a.RuleName)
				ws.Broadcast("new_alert", map[string]interface{}{
					"rule_name": a.RuleName,
					"severity":  strings.ToLower(a.Severity),
					"agent_id":  a.AgentID,
					"pid":       a.PID,
					"comm":      a.Comm,
				})
			}
		}

		// 触发星轨激活
		if grpcSvc != nil && grpcSvc.StarService() != nil {
			corrID := grpcSvc.StarService().HandleMutation(a.AgentID, a.PID)
			log.Printf("⭐ 告警触发星轨: corrID=%s", corrID)

			// 回写 correlation_id 到告警（优先用事件自己的 correlationID）
			alertCorrID := corrID
			if a.CorrelationID != "" {
				alertCorrID = a.CorrelationID
			}
			if psqlDB != nil {
				psqlDB.UpdateAlertCorrelationID(context.Background(), a.AgentID, a.RuleName, alertCorrID)
			}
			// 塞入 Agent 命令队列（下次心跳时下发）
			if h != nil {
				h.Mu.Lock()
				if agent, ok := h.Agents[a.AgentID]; ok {
					agent.Commands = append(agent.Commands, &pb.ProbeCommand{
						Type:        pb.ProbeCommand_ACTIVATE_STAR,
						ProbeName:   "tcp_monitor",
						ProbeConfig: corrID,
					})
					log.Printf("📤 星轨激活命令已塞入 Agent %s 队列", a.AgentID)
				}
				h.Mu.Unlock()
			}
		}
	})
	grpcSvc.SetAlertEngine(alertEngine)
	_ = alert.NewCorrelationEngine("server/configs/correlation.toml")

	// 启动 HTTP
	r := gin.Default()
	r.GET("/ws", gin.WrapF(ws.HandleWS))
	r.StaticFile("/install.sh", "./server/static/install.sh")
	r.Static("/bin", "./server/static")
	if h != nil {
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
