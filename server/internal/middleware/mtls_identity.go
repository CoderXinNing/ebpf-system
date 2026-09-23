package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// IdentityResolver 解析 Agent 身份的接口
type IdentityResolver interface {
	// GetAgentPublicKeyHash L3：获取 DB 中的公钥哈希
	GetAgentPublicKeyHash(ctx context.Context, agentID string) ([]byte, error)
	// IsAgentRevoked L4：检查是否已撤销
	IsAgentRevoked(ctx context.Context, agentID string) (bool, error)
}

// MTLSIdentityInterceptor 4 层校验拦截器
//
// L1 Certificate Trust  : TLS 层已完成（CA 签名 + 有效期 + Key Usage）
// L2 Identity Binding   : 从 SAN URI 提取 agent_id
// L3 Key Binding        : 证书公钥 hash == DB 记录
// L4 Revocation         : DB revoked_at IS NULL
type MTLSIdentityInterceptor struct {
	resolver IdentityResolver
}

func NewMTLSIdentityInterceptor(resolver IdentityResolver) *MTLSIdentityInterceptor {
	return &MTLSIdentityInterceptor{resolver: resolver}
}

// UnaryInterceptor gRPC 一元拦截器
func (i *MTLSIdentityInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Register 和 Enroll 免校验（首次连接还没有证书）
	if info.FullMethod == "/sentinel.Sentinel/Register" ||
		info.FullMethod == "/sentinel.Sentinel/Enroll" {
		return handler(ctx, req)
	}

	// === L2: 从 mTLS 证书的 SAN URI 提取 agent_id ===
	agentID, cert, err := extractAgentIDFromContext(ctx)
	if err != nil {
		log.Printf("🔒 [L2] 提取 agent_id 失败: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "证书无效: %v", err)
	}

	// === L3: 校验证书公钥 hash == DB 记录 ===
	if err := i.verifyKeyBinding(ctx, agentID, cert); err != nil {
		log.Printf("🔒 [L3] Agent %s 公钥绑定失败: %v", agentID, err)
		return nil, status.Errorf(codes.Unauthenticated, "公钥绑定失败")
	}

	// === L4: 检查撤销状态 ===
	revoked, err := i.resolver.IsAgentRevoked(ctx, agentID)
	if err != nil {
		log.Printf("🔒 [L4] Agent %s 撤销状态查询失败: %v", agentID, err)
		return nil, status.Errorf(codes.Internal, "内部错误")
	}
	if revoked {
		log.Printf("🔒 [L4] Agent %s 已撤销，拒绝访问", agentID)
		return nil, status.Errorf(codes.PermissionDenied, "Agent 已被撤销")
	}

	// 全通过，把 agent_id 写入 context（业务层可读）
	ctx = context.WithValue(ctx, "agent_id", agentID)
	return handler(ctx, req)
}

// extractAgentIDFromContext 从 gRPC context 提取客户端证书的 SAN URI
func extractAgentIDFromContext(ctx context.Context) (string, *x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil, fmt.Errorf("无法获取 peer 信息")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", nil, fmt.Errorf("非 TLS 连接")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", nil, fmt.Errorf("无已验证证书链")
	}

	cert := tlsInfo.State.VerifiedChains[0][0]

	// 从 SAN URI 提取 agent_id
	// 格式：spiffe://astertrack/agent/<agent_id>
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" && uri.Host == "astertrack" {
			path := strings.TrimPrefix(uri.Path, "/agent/")
			if strings.HasPrefix(path, "agent-") {
				return path, cert, nil
			}
		}
	}

	return "", nil, fmt.Errorf("证书中未找到 SAN URI spiffe://astertrack/agent/<id>")
}

// verifyKeyBinding L3：证书公钥 hash == DB 记录
func (i *MTLSIdentityInterceptor) verifyKeyBinding(ctx context.Context, agentID string, cert *x509.Certificate) error {
	// 1. 序列化证书公钥为 PKIX DER
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("公钥序列化失败: %w", err)
	}

	// 2. 计算 SHA256
	hash := sha256.Sum256(pubKeyDER)

	// 3. 从 DB 取注册时的 hash
	dbHash, err := i.resolver.GetAgentPublicKeyHash(ctx, agentID)
	if err != nil {
		return fmt.Errorf("查询公钥哈希失败: %w", err)
	}
	if dbHash == nil {
		return fmt.Errorf("Agent 未注册或公钥哈希缺失")
	}

	// 4. 逐字节对比
	if len(dbHash) != len(hash) {
		return fmt.Errorf("公钥哈希长度不一致")
	}
	for idx := range hash {
		if hash[idx] != dbHash[idx] {
			return fmt.Errorf("公钥哈希不匹配")
		}
	}

	return nil
}
