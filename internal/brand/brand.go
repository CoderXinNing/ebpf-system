// Package brand 集中管理品牌与协议常量。
//
// 重要：
//   - SPIFFE 相关常量【冻结】，修改会导致所有已签发证书失效
//   - Agent 和 Server 共享本包，确保协议值严格一致
package brand

const (
	// Name 品牌名（用于 UI / 日志）
	Name = "AsterTrack"

	// AgentVersion Agent 版本号
	AgentVersion = "1.0.0"

	// OrgName 组织名（写入证书 Subject.Organization）
	OrgName = "AsterTrack"

	// CACommonName CA 证书 Subject.CommonName
	CACommonName = "AsterTrack CA"

	// AgentCommonName Agent 证书 Subject.CommonName
	AgentCommonName = "AsterTrack Agent"

	// SPIFFEDomain SPIFFE URI 域名部分（用于 mTLS L2 校验）
	// ⚠️ 冻结：修改会导致所有已签发证书失效
	SPIFFEDomain = "astertrack"

	// SPIFFEAgentPrefix SPIFFE URI 前缀（用于签发 Agent 证书 SAN）
	// ⚠️ 冻结：必须与 SPIFFEDomain 保持一致
	SPIFFEAgentPrefix = "spiffe://astertrack/agent/"
)
