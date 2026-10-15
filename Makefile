# AsterTrack 构建入口
# 目前只固化 proto regen；后续可扩展 build / test / ebpf

PROTO_ROOT := proto/split
PROTO_OUT  := .
GO_MODULE  := github.com/CoderXinNing/ebpf-system

.PHONY: proto
proto:
	@export PATH="$$(go env GOPATH)/bin:$$PATH" && \
	protoc \
	  --go_out=$(PROTO_OUT) --go_opt=module=$(GO_MODULE) \
	  --go-grpc_out=$(PROTO_OUT) --go-grpc_opt=module=$(GO_MODULE) \
	  -I $(PROTO_ROOT) $(PROTO_ROOT)/*.proto
	@echo "✅ proto regenerated"

.PHONY: help
help:
	@echo "make proto  - 重新生成 proto/pb/*.go"
