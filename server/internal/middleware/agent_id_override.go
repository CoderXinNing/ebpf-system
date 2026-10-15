package middleware

import (
	"context"
	"fmt"
	"log"
	"reflect"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AgentIDOverrideInterceptor 用证书身份覆写请求中的 AgentId 字段（BUG-008）。
//
// 背景：
//
//	所有 RPC 都用 req.AgentId 做业务处理，但 req.AgentId 由客户端提供，
//	可被持有任意合法证书的 Agent 伪造 → 冒充其他 agent_id。
//	证书身份（SAN URI）才是唯一事实源。
//
// 语义：
//   - req 有 AgentId 字段时：
//   - 请求值为空 → 覆写为证书身份
//   - 请求值与证书身份一致 → 放行
//   - 请求值非空且不一致 → 拒绝（PermissionDenied）
//   - req 无 AgentId 字段 → 跳过
//
// 必须排在 MTLSIdentityInterceptor 之后，业务 handler 之前。
type AgentIDOverrideInterceptor struct{}

func NewAgentIDOverrideInterceptor() *AgentIDOverrideInterceptor {
	return &AgentIDOverrideInterceptor{}
}

func (i *AgentIDOverrideInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// 从 ctx 取证书身份（MTLSIdentity 已写入）
	agentIDVal := ctx.Value("agent_id")
	if agentIDVal == nil {
		// 无证书身份（如过渡期 Token 路径）→ 不覆写，走原逻辑
		return handler(ctx, req)
	}
	agentID, ok := agentIDVal.(string)
	if !ok || agentID == "" {
		return nil, status.Errorf(codes.Internal, "context agent_id 非法")
	}

	if err := overwriteAgentID(req, agentID); err != nil {
		log.Printf("🔒 [Override] %s 拒绝: %v", info.FullMethod, err)
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}

	return handler(ctx, req)
}

// overwriteAgentID 用反射把 req 的 AgentId 字段覆写为证书身份。
func overwriteAgentID(req interface{}, agentID string) error {
	v := reflect.ValueOf(req)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return nil
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return nil
	}

	f := v.FieldByName("AgentId")
	if !f.IsValid() || f.Kind() != reflect.String {
		return nil
	}
	if !f.CanSet() {
		return nil
	}

	existing := f.String()
	if existing != "" && existing != agentID {
		return fmt.Errorf("请求 agent_id (%s) 与证书身份 (%s) 不一致", existing, agentID)
	}
	f.SetString(agentID)
	return nil
}
