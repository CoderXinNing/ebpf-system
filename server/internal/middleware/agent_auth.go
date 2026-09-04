package middleware

import (
	"context"
	"log"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AgentAuthInterceptor 验证 Agent token 的 Unary Interceptor。
// token 从 gRPC Metadata 的 "authorization" 键获取，格式为 "Bearer <token>"。
// 只有 Register 方法不需要 token。
type AgentAuthInterceptor struct {
	mu     sync.RWMutex
	tokens map[string]string // agent_id -> token
}

func NewAgentAuthInterceptor() *AgentAuthInterceptor {
	return &AgentAuthInterceptor{
		tokens: make(map[string]string),
	}
}

// SetToken 注册或更新 Agent 的 token
func (i *AgentAuthInterceptor) SetToken(agentID, token string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.tokens[agentID] = token
}

// RemoveToken 删除 Agent 的 token（下线时）
func (i *AgentAuthInterceptor) RemoveToken(agentID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.tokens, agentID)
}

// VerifyToken 验证 token 是否匹配
func (i *AgentAuthInterceptor) VerifyToken(agentID, token string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	expected, ok := i.tokens[agentID]
	return ok && expected == token
}

// UnaryInterceptor 是 gRPC Unary 拦截器
func (i *AgentAuthInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Register 方法免鉴权
	if info.FullMethod == "/sentinel.Sentinel/Register" {
		return handler(ctx, req)
	}

	// 从 Metadata 提取 token
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "缺少 Metadata")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "缺少 authorization 头")
	}

	// 解析 "Bearer <token>"
	authHeader := authHeaders[0]
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return nil, status.Errorf(codes.Unauthenticated, "authorization 格式错误")
	}
	token := authHeader[7:]

	// 从请求中提取 agent_id（各请求类型都有 AgentId 字段）
	agentID := extractAgentID(req)
	if agentID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "缺少 agent_id")
	}

	// 验证 token
	if !i.VerifyToken(agentID, token) {
		log.Printf("🔒 Agent %s token 验证失败", agentID)
		return nil, status.Errorf(codes.Unauthenticated, "token 无效")
	}

	return handler(ctx, req)
}

// extractAgentID 从各种请求类型中提取 AgentId 字段
func extractAgentID(req interface{}) string {
	type agentIDGetter interface {
		GetAgentId() string
	}
	if getter, ok := req.(agentIDGetter); ok {
		return getter.GetAgentId()
	}
	return ""
}
