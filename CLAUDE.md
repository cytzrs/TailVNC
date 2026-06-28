# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目定位

TailVNC 是一个 **Windows 远程桌面（VNC）服务端**，用 Go 编写，可选择性内嵌 Tailscale WireGuard（`tsnet`），编译为单文件 `.exe`。用于合法的远程基础设施运维。仅目标平台 **Windows amd64**，Go 1.25.3。

整个 `cmd/vnc/` 与 `pkg/vnc/` 下的所有 `.go` 文件都带 `//go:build windows`。这是刻意设计：纯协议逻辑被抽到不带 build tag 的包里，使其能在任意平台单元测试（见下「协议纯逻辑分层」）。

## 开发环境关键约束：Linux 上开发 / Windows 上运行

本仓库在 Linux 上开发，但产物是 Windows exe。理解 build-tag 分裂是一切的前提：

- `go test ./...` 在 Linux 上**能跑且只跑跨平台包**：windows-only 包被 build 约束静默排除，输出里只会出现 `pkg/rfbcore`、`pkg/authtoken`、`pkg/secureroot`、`pkg/secrets`、`pkg/obfkey`（5 个包有测试，全过）。不会报错。
- **绝不能在 Linux 上直接改 `pkg/vnc` 或 `cmd/vnc` 的代码就当完事**——它们在本机编不过、跑不了。改完必须用 `GOOS=windows` 验证（见下）。
- Windows 代码的编译/静态检查通过交叉编译完成，不需要 Windows 机器。

## 常用命令

```bash
# 跨平台纯逻辑包：测试 + 竞态 + 覆盖率（本机直接跑，无需 Windows）
go test ./...
go test -race ./pkg/...
go test -cover ./pkg/rfbcore

# 跑单个测试
go test ./pkg/rfbcore/ -run TestReverseBits -v

# 验证 Windows 代码（本机交叉编译/vet，不执行）
GOOS=windows GOARCH=amd64 go vet ./...        # 静态检查 windows 代码
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./cmd/vnc   # 交叉编译冒烟

# 正式发布构建（清理→deps→混淆 auth key→LDFLAGS 注入→-s -w→可选 UPX）
make build-vnc LISTEN_PORT=5900 AUTH_PASS=Passw0rd                       # 纯 TCP
make build-vnc AUTH_KEY=$TSKEY LISTEN_PORT=5900 AUTH_PASS=Passw0rd        # 内嵌 tsnet
make help        # 参数速查
```

> 已知 vet 噪音：`pkg/vnc/clipboard.go` 两处 `unsafe.Pointer` misuse（QUAL-1，明确**暂缓**到 Windows VM 处理，见提交 `1cd439c`）。不要顺手"修"掉。

依赖：仅 `golang.org/x/sys` 与 `tailscale.com v1.92.0`（tsnet）。`AUTH_KEY` 从**环境变量**读，绝不进 argv/ldflags/构建日志（SEC-6）。

## 架构：双进程模型（理解全局的钥匙）

跨 `main.go` + `server.go` + `agent.go` + `ipc.go` 才能看清的核心设计——**Chrome Remote Desktop 式的 Session 0 服务 + 用户会话 agent**：

1. `main.go` 入口先判断 `--agent <port>`：是则进 `runAgent`（在 127.0.0.1 起一个本地 VNC server）。
2. 否则按当前 Windows Session ID 分流（`serve()`）：
   - Session 0（SYSTEM/服务）→ `Server.RunAsService`
   - 交互式会话 → `Server.RunLocal`（直接截屏+注入，无 agent）

**为什么必须有 agent**：GDI `BitBlt` 从 Session 0 截屏永远是黑屏——显示内容归用户会话（Session 1）的 DWM 所有。所以服务进程把**自己**用 `CreateProcessAsUser` 重 exec 到用户会话里当 agent，由 agent 看到真实像素。

**为什么 agent 用 SYSTEM token 而非用户 token**（`agent.go:55` 注释，关键不变量）：把 SYSTEM token 的会话 ID 改写后投放到目标会话。这样 agent 既能 `OpenInputDesktop/SetThreadDesktop` 访问**安全桌面**（Winlogon/UAC），又能以 SYSTEM 身份 `SendInput` 绕过 UIPI。用用户 token 会在安全桌面激活时 `ERROR_ACCESS_DENIED`。

**服务↔agent 流量**：服务对每个进来的 VNC 连接起一个 `proxyToAgent` goroutine，双向裸 TCP 透传字节到 `127.0.0.1:15900`。agent 的 loopback listener 被 `authtoken.Listener` 包裹，要求连接先发送一次性 token（SEC-2，见下）。

`sessionManager`（`agent.go`）每 2s 轮询活动控制台会话：会话变化或 agent 退出就 kill+重生 agent，每次重生**轮换**新的 IPC token。

## 安全 / IPC 链路（当前正在做的 M1 工作）

仓库正处于一轮**安全地基整改**，提交用 `SEC-N`/`CORR-N`/`QUAL-N`/`PERF-N`/`LIFE-N`/`OPS-N` 标签。设计依据在 `docs/superpowers/specs/2026-06-25-tailvnc-full-remediation-design.md`，M1 实施计划在 `docs/superpowers/plans/`。改动请沿用这套标签 + 里程碑结构。

已落地的安全链（按连接路径）：

- **SEC-1** 默认绑定 `127.0.0.1`（暴露须显式 `LISTEN_ADDR`）；VNCAuth 失败按来源地址指数退避（`rfb.go` `authBackoff`，封顶 30s）。
- **SEC-2** 一次性 IPC token：`agent.go:spawnAgentInSession` 用 `authtoken.Generate(32)` 生成，经**手搓的最小环境块**（只含 `TAILVNC_AGENT_TOKEN`）注入 agent；agent 端 `authtoken.Listener` 用 `subtle.ConstantTimeCompare` 校验，错则关连接继续 Accept（防本地坏进程 DoS accept 循环）。
- **SEC-4** `secureroot.IsInSecureDir`：拒绝从非管理员可写目录 re-exec 自己（防可写路径 LPE）。注意 `SystemRoot` 被**收窄到 System32**，避免 `C:\Windows\Temp`（用户可写）漏过。完整 DACL 校验**明确暂缓到 M3**。
- **SEC-6** 密钥/密码经 `secrets.FromEnvOrFile` 从环境/受保护文件读，不经 argv。

认证/配置优先级：运行时 `--auth-key`/`--auth-pass` > `TAILVNC_AUTH_PASS` 环境变量 > 构建时 `AUTH_KEY`/`AUTH_PASS`（LDFLAGS）。**VNC 密码强制**——构建与运行时都没有就 `log.Fatal` 拒启动。`AUTH_KEY` 为空 = 纯 TCP 模式（不启 tsnet）。

## 不可违反的不变量

- **OS 线程锁定**（`screen.go:loop`、`server.go:DesktopAwareInput.loop`）：截屏 goroutine 与输入 goroutine 都 `runtime.LockOSThread()` 终身锁定。因为 `SetThreadDesktop` 只影响调用它的那条 OS 线程，Go 调度器会在 `time.Sleep` 后把 goroutine 迁到别的线程，导致 `GetDC(0)`/`SendInput` 落在持有陈旧桌面关联的线程上。新增任何走桌面/SendInput 的 goroutine 都必须先锁线程。
- **脏矩形读写必须在 `c.mu` 内**（`screen.go:loop`，CORR-3）：`staticFrames` 的自适应帧率判断要在锁内读 `c.dirty`，否则与 `CaptureDirty` 消费者竞态。`-race` 必须通过。
- **输入状态 per-session**（`input.go:inputState`，CORR-2）：`prevButton`/`ctrlDown`/`altDown` 挂在 session 上，不能是包级全局，否则并发客户端互相串状态。
- **zlib 失败必须连 encoding 一起降级到 Raw**（`rfbcore.EncodeDirtyRect`，CORR-1）：绝不发"标 encZlib 装原始字节"的 rect，会腐化客户端流。

## 协议纯逻辑分层（新代码归属判断）

`pkg/rfbcore`（仅依赖标准库，无 build tag）= RFB 协议的纯逻辑：`VncAuthEncrypt`/`ReverseBits`（VNC DES 认证）、`DiffFrames`（32px tile 脏矩形 diff）、像素格式编解码（`EncodePixelsFast` 快速路径 / `EncodePixelsGeneric` 通用路径）、`ZlibCompress`、Latin-1↔UTF-8。覆盖率达 92%+。

**判断准则**：新写的协议/像素/diff 逻辑若纯计算、不碰 Windows API，应放进 `pkg/rfbcore` 并配表驱动测试（跨平台可跑）。只有真正调 Win32 syscall（GDI/user32/wtsapi32/sas 等）的代码才留在 `pkg/vnc` 的 `//go:build windows` 文件里，并尽量把可测纯逻辑 delegate 给 rfbcore。这就是 Phase 0 / TEST-1 拆分的延续。

`pkg/vnc/rfb.go` 的 `session` 是 RFB 3.008 的握手+消息循环（Raw/Zlib 编码），通过 `ScreenCapturer`/`InputInjector`/`ClipboardBridge` 三个接口与具体实现解耦。

## 桌面跟踪 / SAS / 带宽优化

- **桌面跟踪**：`switchToInputDesktop`（`OpenInputDesktop`+`SetThreadDesktop`）让 agent 自动跟随 Default/Winlogon/UAC/锁屏桌面，无需知道会话 ID。桌面切换可能带来分辨率变化 → `session.syncDims()` 在每次 `handleFBUpdateRequest`/`handlePointerEvent` 入口从 capturer 实时同步 `serverW/H`（修坐标错位 + clamp 越界，Bug 4）。
- **Ctrl+Alt+Del → SAS**：`SendInput` 注入不了安全注意序列。agent 检测到 Ctrl+Alt+Del（`input.go:keyEvent`）后通过命名事件 `Global\TailVNC_SAS` 通知服务进程，由**服务（Session 0）**调 `sas.dll!SendSAS(FALSE)`（`server.go:startSASListener`）。
- **带宽优化**（提交 `52d0a74`）：脏矩形 diff（`DirtyTileSize=32`，超 `MaxDirtyRects=256` 降级全屏）+ 客户端支持时 zlib 压缩 + 自适应帧率（动态 30fps / 静态 ~10fps）+ 无变化时发空 `FramebufferUpdate`（让客户端停止轮询，静态桌面接近 0 带宽）。

## 构建期配置注入

`main.go` 用一组 `buildWith*` 包级变量承接 LDFLAGS `-X` 注入：`version`/`buildTime`/`buildWithObfuscatedAuthKey`/`buildWithControlURL`/`buildWithListenPort`/`buildWithAuthPass`/`buildWithConfigDir`/`buildWithListenAddr`。`AUTH_KEY` 在构建时经 `obfuscator/`（AES-256-CTR，每构建随机 nonce，输出 `hex(nonce‖ct)`）加密后注入；运行时 `pkg/deobfuscator` 还原。AES key 单一来源在 `pkg/obfkey`（SEC-3/QUAL-2）。命令行解析是手搓的 `flagValue`（QUAL-3 待改标准 `flag` 包）。

> 安全诚实性（README 已对齐）：混淆 key 内嵌于二进制，**不能防逆向**，只移除 `strings`/hex 明文。Tailscale auth key 一旦落入攻击者之手视同明文——用短期、受限的 key。
