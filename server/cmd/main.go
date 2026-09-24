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
	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/alert"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/build"
	"github.com/CoderXinNing/ebpf-system/server/internal/ca"
	"github.com/CoderXinNing/ebpf-system/server/internal/grpcservice"
	"github.com/CoderXinNing/ebpf-system/server/internal/handler"
	"github.com/CoderXinNing/ebpf-system/server/internal/middleware"
	"github.com/CoderXinNing/ebpf-system/server/internal/model"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository/psql"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository/sqlite"
	"github.com/CoderXinNing/ebpf-system/server/internal/udp"
	"github.com/CoderXinNing/ebpf-system/server/internal/ws"
	"github.com/gin-gonic/gin"
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
		CertFile            string `toml:"cert_file"`
		KeyFile             string `toml:"key_file"`
		CAFile              string `toml:"ca_file"`
		StrictMTLS          bool   `toml:"strict_mtls"`
		CertificateTTLHours int    `toml:"certificate_ttl_hours"`
	} `toml:"tls"`
	Build struct {
		GoPath         string `toml:"go_path"`
		AutoBuildAgent bool   `toml:"auto_build_agent"`
	} `toml:"build"`
}

func main() {
	cfg := loadConfig("server/configs/server.toml")
	if cfg == nil {
		log.Println("⚠️ 使用默认配置")
		cfg = defaultConfig()
	}

	// 编译 Agent（源码变化才重编）
	if err := build.EnsureAgentBinary(build.Config{
		GoPath:         cfg.Build.GoPath,
		AutoBuildAgent: cfg.Build.AutoBuildAgent,
	}); err != nil {
		log.Printf("⚠️ Agent 编译检查失败: %v", err)
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
			h.SetSaveAssetFunc(func(agentID string, processesJSON, usersJSON, systemJSON []byte) error {
				log.Printf("DEBUG: SaveAssetFunc processes=%d bytes users=%d bytes system=%d bytes", len(processesJSON), len(usersJSON), len(systemJSON))
				return psqlDB.SaveAsset(context.Background(), agentID, processesJSON, usersJSON, systemJSON)
			})
			h.SetSettingCallbacks(
				func(key string) (string, error) {
					return psqlDB.GetLogSetting(context.Background(), key)
				},
				func(key, value string) error {
					return psqlDB.SetLogSetting(context.Background(), key, value)
				},
				func() (map[string]string, error) {
					return psqlDB.ListSettings(context.Background())
				},
			)
			// 证书初始化（首次运行自动生成 CA + Server 证书；旧品牌 CA 会报错退出）
			if _, err := ca.Bootstrap(ca.BootstrapOptions{
				Dir:               "certs",
				ServerCommonName:  "localhost",
				ServerDNSNames:    []string{"localhost", "*.localhost"},
				ServerIPAddresses: collectLocalIPs(),
			}); err != nil {
				log.Fatalf("❌ 证书初始化失败: %v", err)
			}

			// 加载 CA
			caInstance, err := ca.Load("certs/ca.crt", "certs/ca.key")
			if err != nil {
				log.Printf("⚠️ CA 加载失败: %v（enrollment 不可用）", err)
			} else {
				h.CACertPEM = caInstance.CertPEM()
				h.ComputeAgentIDFunc = ca.ComputeAgentID
				h.SignCSRFunc = func(csrPEM []byte, agentID string, ttlHours int) ([]byte, string, time.Time, error) {
					if ttlHours <= 0 {
						ttlHours = cfg.TLS.CertificateTTLHours
						if ttlHours <= 0 {
							ttlHours = 8760
						}
					}
					return caInstance.SignCSR(csrPEM, agentID, time.Duration(ttlHours)*time.Hour)
				}
				h.EnrollAgentFunc = func(req handler.EnrollRequest) (*handler.EnrollResult, error) {
					res, err := psqlDB.EnrollAgent(context.Background(), psql.EnrollRequest{
						Token:        req.Token,
						AgentID:      req.AgentID,
						Hostname:     req.Hostname,
						IPAddr:       req.IPAddr,
						MachineID:    req.MachineID,
						MAC:          req.MAC,
						PublicKeyDER: req.PublicKeyDER,
					})
					if err != nil {
						return nil, err
					}
					return &handler.EnrollResult{
						AgentID:   res.AgentID,
						GroupID:   res.GroupID,
						GroupName: res.GroupName,
					}, nil
				}
				h.UpdateAgentCertFunc = func(agentID, serial string, expiresAt time.Time) error {
					return psqlDB.UpdateAgentCert(context.Background(), agentID, serial, expiresAt)
				}
				h.GetAgentPublicKeyHashFunc = func(agentID string) ([]byte, error) {
					return psqlDB.GetAgentPublicKeyHash(context.Background(), agentID)
				}
				h.RenewCertFunc = h.RenewCertHandler
				h.RevokeAgentFunc = func(agentID string) error {
					return psqlDB.RevokeAgent(context.Background(), agentID)
				}
				h.DeleteAgentFunc = func(agentID string) error {
					return psqlDB.DeleteAgent(context.Background(), agentID)
				}
				h.ReloadAgentsFunc = func() (int, error) {
					agents, err := psqlDB.ListAgents(context.Background(), nil)
					if err != nil {
						return 0, err
					}
					h.Mu.Lock()
					h.Agents = make(map[string]*handler.AgentInfo)
					for _, a := range agents {
						h.Agents[a.ID] = &handler.AgentInfo{
							ID:              a.ID,
							Hostname:        a.Hostname,
							IPAddr:          a.IPAddr,
							Version:         a.Version,
							CapabilityLevel: a.CapabilityLevel,
							ActiveProbes:    a.ActiveProbes,
							BaselineState:   a.BaselineState,
							FirstSeen:       a.FirstSeen.Unix(),
							LastSeen:        a.LastSeen.Unix(),
							Commands:        make([]*pb.ProbeCommand, 0),
						}
					}
					h.Mu.Unlock()
					return len(agents), nil
				}
				h.GenerateTokenFunc = func(name string, groupID *int64, maxUses int, ttlHours int, createdBy string) (string, error) {
					return psqlDB.GenerateToken(context.Background(), name, groupID, maxUses, time.Duration(ttlHours)*time.Hour, createdBy)
				}
				h.ListTokensFunc = func() ([]map[string]interface{}, error) {
					tokens, err := psqlDB.ListTokens(context.Background())
					if err != nil {
						return nil, err
					}
					result := make([]map[string]interface{}, 0, len(tokens))
					for _, t := range tokens {
						result = append(result, map[string]interface{}{
							"id":         t.ID,
							"name":       t.Name,
							"group_id":   t.GroupID,
							"max_uses":   t.MaxUses,
							"used_count": t.UsedCount,
							"expires_at": t.ExpiresAt,
							"created_by": t.CreatedBy,
							"created_at": t.CreatedAt,
							"revoked_at": t.RevokedAt,
						})
					}
					return result, nil
				}
				h.RevokeTokenFunc = func(id int64) error {
					return psqlDB.RevokeToken(context.Background(), id)
				}
				log.Println("✅ CA 已加载，enrollment 可用")
			}

			h.SetSaveTypedAssetFunc(func(agentID, assetType, assetName string, data interface{}) error {
				return psqlDB.SaveTypedAsset(context.Background(), agentID, assetType, assetName, data)
			})
			h.SetGetAllAssetsFunc(func(agentID string) (map[string]interface{}, error) {
				return psqlDB.GetAllAssets(context.Background(), agentID)
			})
			h.SetGetLatestAssetFunc(func(agentID string) (interface{}, interface{}, interface{}, error) {
				processes, users, system, err := psqlDB.GetLatestAsset(context.Background(), agentID)
				if err != nil {
					return nil, nil, nil, err
				}
				return processes, users, system, nil
			})
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
			h.SetListWhitelistFunc(func() ([]string, error) {
				return psqlDB.ListWhitelist(context.Background())
			})
			h.SetAddWhitelistFunc(func(processName, reason string) error {
				return psqlDB.AddWhitelist(context.Background(), processName, reason, "admin")
			})
			h.SetRemoveWhitelistFunc(func(processName string) error {
				return psqlDB.RemoveWhitelist(context.Background(), processName)
			})
			h.SetUpdateAlertStatusFunc(func(ids []int64, status string) error {
				return psqlDB.UpdateAlertStatus(context.Background(), ids, status)
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
					AgentID:       evt.AgentID,
					ProbeName:     evt.ProbeName,
					EventType:     evt.EventType,
					PID:           int32(evt.PID),
					Comm:          evt.Comm,
					Filename:      evt.Filename,
					Details:       evt.Details,
					CorrelationID: evt.CorrelationID,
					SourceChannel: "grpc",
					Timestamp:     time.Unix(evt.Timestamp, 0),
				})
			})
		}
	}

	agentAuth := middleware.NewAgentAuthInterceptor()

	// gRPC Service
	grpcSvc := grpcservice.NewService(h, agentAuth)

	// 从 DB 加载已有 Agent（Server 重启后恢复内存状态）
	loadAgentsFromDB(h, psqlDB)

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

	// 拦截器链
	var unaryInterceptors []grpc.UnaryServerInterceptor

	// MTLS 4 层校验（Day 2-3，过渡期可关闭）
	enableStrictMTLS := cfg.TLS.StrictMTLS
	if enableStrictMTLS && psqlDB != nil {
		mtlsInterceptor := middleware.NewMTLSIdentityInterceptor(psqlDB)
		unaryInterceptors = append(unaryInterceptors, mtlsInterceptor.UnaryInterceptor)
		log.Println("🔐 [L1-L4] mTLS 四层校验已启用（跳过 Token 校验）")
	} else {
		// 过渡期：使用 Token 校验
		unaryInterceptors = append(unaryInterceptors, agentAuth.UnaryInterceptor)
		log.Println("⚠️ mTLS 四层校验未启用（过渡期，使用 Token 校验）")
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
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

	// 启动时从 PSQL 加载白名单
	go func() {
		time.Sleep(2 * time.Second)
		list, err := psqlDB.ListWhitelist(context.Background())
		if err == nil && len(list) > 0 {
			h.Mu.Lock()
			h.Whitelist = list
			h.Mu.Unlock()
			alertEngine.SetWhitelist(list)
			log.Printf("📥 白名单已加载: %d 条", len(list))
		}
	}()
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
	cfg.TLS.StrictMTLS = false
	cfg.TLS.CertificateTTLHours = 8760
	cfg.Build.GoPath = ""
	cfg.Build.AutoBuildAgent = true
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

// loadAgentsFromDB 启动时从数据库加载 Agent 到内存
// 目的：Server 重启后前端能看到已注册的主机
// 说明：不恢复 token（DB 只存 hash），Agent 会通过重新注册获取新 token
func loadAgentsFromDB(h *handler.Handler, db *psql.PSQL) {
	if h == nil || db == nil {
		return
	}

	agents, err := db.ListAgents(context.Background(), nil)
	if err != nil {
		log.Printf("⚠️ 从 DB 加载 Agent 失败: %v", err)
		return
	}

	h.Mu.Lock()
	defer h.Mu.Unlock()

	loaded := 0
	for _, a := range agents {
		h.Agents[a.ID] = &handler.AgentInfo{
			ID:              a.ID,
			Hostname:        a.Hostname,
			IPAddr:          a.IPAddr,
			Version:         a.Version,
			CapabilityLevel: a.CapabilityLevel,
			ActiveProbes:    a.ActiveProbes,
			BaselineState:   a.BaselineState,
			FirstSeen:       a.FirstSeen.Unix(),
			LastSeen:        a.LastSeen.Unix(),
			Commands:        make([]*pb.ProbeCommand, 0),
		}
		loaded++
	}
	log.Printf("📥 已从 DB 加载 %d 个 Agent 到内存", loaded)
}

// collectLocalIPs 收集本机 IP，用于 Server 证书的 SAN IP 字段。
// 包含：127.0.0.1、::1，以及所有非 loopback 的 IPv4。
// 用途：Server 证书 SAN IP 需匹配 Agent 实际连接的地址（如 172.16.2.145）。
func collectLocalIPs() []string {
	ips := []string{"127.0.0.1", "::1"}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ips = append(ips, v4.String())
		}
	}
	return ips
}
