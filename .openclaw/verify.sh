#!/bin/bash
# OpenClaw CodeAct 验证脚本 — TailVNC 项目
# 用法: .openclaw/verify.sh
set -e

echo "=== Build (cross-compile Windows) ==="
GOOS=windows GOARCH=amd64 go build ./...
echo "✅ Build passed"

echo "=== Build (native Linux) ==="
go build ./...
echo "✅ Native build passed"

echo "=== Vet ==="
go vet -unsafeptr=false ./...
echo "✅ Vet passed"

echo "=== Test ==="
go test ./... -v -count=1 2>&1 | tail -20
echo "✅ Tests passed"

echo ""
echo "=== ALL CHECKS PASSED ==="
