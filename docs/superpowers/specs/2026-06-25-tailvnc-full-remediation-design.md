# TailVNC 全量整改设计（Full Remediation Design）

- **日期**: 2026-06-25
- **状态**: Draft — 待用户 review 后交 writing-plans 出实施计划
- **定位**: **合法远程基础设施运维工具**（legitimate remote infrastructure administration）。非红队/免杀定位。
- **推进策略**: 策略 1 — 里程碑式、测试先行（M1 安全 → M2 互操作/性能 → M3 运维/文档）。

---

## 1. 背景

两轮审计（grill + 深挖）共发现 20+ 项问题，覆盖安全/提权、协议正确性、性能、生命周期、可测试性。
本设计给出按依赖顺序排列的完整整改方案。每项含：问题、修复、验收标准、依赖、风险。

定位决策的影响：合法运维口径下，原"OPSEC/隐蔽"相位退化为"可靠性与安全卫生"——
去指纹、随机主机名等**反检测**项被显式下架（见 §6 OPS 相位）。

---

## 2. 目标 / 非目标

### 目标
1. 消除本地提权面与认证薄弱（M1 核心）。
2. 让标准 VNC 客户端稳定可用、分辨率切换不断流（M2）。
3. 可测试、可观测、可干净退出（M1/M3）。
4. 提供**合法、显式、管理员可管理**的持久化（SCM 服务）。

### 非目标（显式排除）
- 红队隐蔽、免杀、反取证。
- Tight / H.264 / WebP 等重编码升级（超范围，性能相位只做无编码变更的优化）。
- 跨平台（仍仅 Windows amd64）。

---

## 3. Findings 索引（统一编号 · 含证据 file:line）

| ID | 问题 | 证据 |
|----|------|------|
| **TEST-1** | 零测试，且 Windows-only 在 Linux 编不出 | `find *_test.go` = 0 |
| **SEC-1** | 直连默认 `0.0.0.0` + VNC DES 弱认证（≤8 字节密码、单 DES） | `main.go:181`, `rfb.go:260` |
| **SEC-2** | 本地 agent 监听 `127.0.0.1:15900` 无认证（secNone） | `main.go:78`, `rfb.go:179` |
| **SEC-3** | AES 混淆 key 硬编码在二进制内（安全剧场）+ README XOR/AES 自相矛盾 | `deobfuscate_key_hex.go:10`, `README.md:15 vs 59` |
| **SEC-4** | SYSTEM 服务从 `os.Executable()` 路径重 exec 自己 → 可写路径 LPE | `agent.go:110,135` |
| **SEC-5** | Agent 全程以 SYSTEM 跑，RFB 解析器暴露在 SYSTEM 上下文 | `agent.go:58` |
| **SEC-6** | 密钥/密码以明文进构建进程命令行（`ps`/日志/历史） | `Makefile:5` |
| **CORR-1** | zlib 失败回退返回原始字节，但 rect 头仍标 `encZlib` → 协议错误 | `rfb.go:486,638` |
| **CORR-2** | 输入状态全局变量（`prevButtonMask`/`sasCtrl`/`sasAlt`）跨连接共享，无锁 | `input.go:113,237` |
| **CORR-3** | `staticFrames` 在锁外读 `c.dirty` → data race | `screen.go:450` |
| **CORR-4** | 未知客户端消息类型直接断连（违反 RFB，真实客户端易掉线） | `rfb.go:358` |
| **CORR-5** | 无伪编码：分辨率变化不发 DesktopSize → 客户端 desync；无鼠标形状 | `grep` 确认无 |
| **PERF-1** | 全动态内容下自适应帧率永远顶 30fps + 全屏更新 | `screen.go:450-452,283` |
| **PERF-2** | 捕获侧每帧 `NewRGBA` + 标量 BGRA→RGBA 循环（~250MB/s 分配） | `screen.go:205-211` |
| **PERF-3** | 剪贴板每 500ms 强占剪贴板，影响其他程序 | `clipboard.go:146` |
| **FUNC-1** | 剪贴板仅 Latin-1，中文等非 Latin-1 字符被替换为 `?` | `clipboard.go:177` |
| **LIFE-1** | 生产环境无日志（`setupFileLog` 全注释） | `main.go:69,140` |
| **LIFE-2** | 无 `context.Context`/信号处理/优雅退出 | `grep` 确认无 |
| **LIFE-3** | agent 端口固定 15900，冲突 → `log.Fatalf` → 2s 重生 → flapping | `agent.go:15,74,195` |
| **LIFE-4** | 代理重试堆 goroutine；单 `writeMu` 写瓶颈；无 FBU 请求限速 | `ipc.go:20`, `rfb.go:69` |
| **OPS-1** | UPX 无条件压缩 → 杀软误杀 + 破坏签名 | `Makefile:48` |
| **OPS-2** | ServerInit name 硬编码 `GoVNC`（合法运维：仅改为可配置，**不去指纹**） | `rfb.go:295` |
| **OPS-3** | agent 端口固定 + WireGuard 私钥明文落盘 | `agent.go:15`, `main.go:147` |
| **OPS-4** | "持久化"名不副实（无 SCM 安装器，重启即失效） | `grep` 确认无 SCM |
| **QUAL-1** | `go vet` 报 4 处 `unsafe.Pointer` 误用 | `agent.go:132`, `clipboard.go:48,74`, `screen.go:202` |
| **QUAL-2** | AES `obfuscateKey` 在两个文件重复硬编码 | `obfuscate_key_hex.go:18`, `deobfuscate_key_hex.go:10` |
| **QUAL-3** | 手搓 flag 解析（无 `--flag=val`/`--help`/未知参数报错） | `main.go:48` |
| **QUAL-4** | `des.NewCipher` 错误被吞 | `rfb.go:268` |
| **QUAL-5** | `winInput` 结构体手工 padding 写死 64-bit | `input.go:65` |
| **DOC-1** | README XOR/AES 矛盾、持久化措辞夸大、无 LICENSE、dual-use 措辞需转向合法运维 | `README.md`, 无 `LICENSE` |

> 合法运维反转项（**下架**）：去指纹（OPS-2 随机化部分）、随机主机名（原 M5）。
> 理由：合法运维下可识别性与真实主机名是**运维需要**。

---

## 4. 总体架构变更

### 4.1 测试分层（解锁 TEST-1，是一切前提）
```
pkg/vnc/        ← 现状：Windows syscall 与纯逻辑混在一起
  ├─ syscalls_windows.go   //go:build windows  （GDI32/USER32/WTS 等）
  ├─ rfb.go                纯协议逻辑（跨平台可测）
  ├─ screen_diff.go        diffFrames（纯逻辑）
  ├─ pixelfmt.go           像素格式编/解码（纯逻辑）
  └─ *_test.go             表驱动，任意平台可跑
```
- 所有 Windows DLL 调用集中到 `//go:build windows` 文件；纯逻辑函数不依赖 syscall → Linux 上 `go test` 可跑。
- 新增 `pkg/vnc/rfb_loopback_test.go`：进程内 server + 极简 client，验证握手/认证/FBU/脏矩形，不依赖 Windows。

### 4.2 运行时与配置分层
- **配置源**：密钥/密码从受保护配置文件（`%ProgramData%\TailVNC\config`，ACL 仅 SYSTEM/Admins）或环境变量读，**不经 argv / 不进 ldflags 进程列表**（SEC-6）。
- **网络/认证层**（service, Session 0）：终止 VNC 握手与认证。
- **IPC 层**：service↔agent 改为**带认证的本地通道**（一次性 token，或带 DACL 的 named pipe），替换裸 TCP 15900（SEC-2, OPS-3）。
- **捕获/输入层**（agent, 用户会话）：权限边界收敛（SEC-5），RFB 解析加固。

---

## 5. 里程碑分解

| 里程碑 | 范围 | 风险 | 产出 |
|--------|------|------|------|
| **M1** | TEST-1, SEC-1..6, CORR-1..3 | 高（动认证/IPC/提权面） | 可上线的最小安全版 |
| **M2** | CORR-4..5, PERF-1..3, FUNC-1, OPS-1..3 | 中 | 真实客户端稳定 + 性能 |
| **M3** | OPS-4, LIFE-1..4, QUAL-1..5, DOC-1 | 低 | 可运维 + 文档对齐 |

依赖：TEST-1 必须最先；M1 内部 SEC-6（配置源）应早于 OPS-4 安装器；M2/M3 大体独立。

---

## 6. 各相位详细设计

### Phase 0 — 测试地基（M1 首块）· TEST-1
- **修复**：按 §4.1 拆分 build tag；为 `diffFrames`、`vncAuthEncrypt`/`reverseBits`、`keysym2VK`、Latin-1 双向转换、RFB 报文编/解码、像素 fast-path 写表驱动测试；新增 loopback 集成测试。
- **验收**：纯逻辑层覆盖率 ≥80%；`go test ./...` 在 Linux 通过（Windows-only 代码用 build tag 隔离）。
- **依赖**：无。
- **风险**：拆分 build tag 可能漏改 import；用 `GOOS=windows go vet ./...` 与 `GOOS=linux go test ./...` 双向验证。

### Phase 1 — 安全加固（M1 核心）· SEC-1..6
- **SEC-1 认证/绑定**：默认 `LISTEN_ADDR=127.0.0.1`，暴露须显式声明；VNCAuth 增加失败计数 + 指数退避（防爆破）。评估升级到 VeNCrypt/TLS（M1 内决策点，见 §9）。
- **SEC-2 本地 IPC 认证**：service 启动 agent 时生成一次性 token，经环境块或命令行注入；agent 监听要求该 token；或改 named pipe + DACL（仅 SYSTEM/Admins 可连）。**验收**：非授权本地进程连 IPC 被拒；新增测试覆盖握手拒绝路径。
- **SEC-4 exePath LPE**：re-exec 前校验 exePath 所在目录 ACL（必须 admin 可写）；安装时强制拷贝到 `%ProgramFiles%\TailVNC\`。**验收**：可写目录下拒绝 re-exec 并记日志。
- **SEC-5 权限收敛**：保持 agent 访问安全桌面所需的最小特权；对 RFB 解析路径加严格长度校验与无界工作上限（与 LIFE-4 限速协同）。
- **SEC-6 密钥配置源**：见 §4.2，构建侧混淆器从 env 读密钥（`AUTH_KEY` 环境变量），Makefile 不再把明文 key 拼进 `go run` 参数。
- **SEC-3 混淆诚实化**：在 README/代码注释明确"混淆仅防静态字符串扫描，不能防逆向"（已部分有），消除 XOR/AES 矛盾；`obfuscateKey` 抽到单一共享常量（兼修 QUAL-2）。
- **依赖**：Phase 0（要能验证）。
- **风险**：VeNCrypt/TLS 若纳入 M1 会显著放大工作量（见 §9 开放问题）。

### Phase 2 — 正确性/并发（M1 收尾 + M2）· CORR-1..5
- **CORR-1**：zlib 失败时**连 encoding 标记一起降级到 Raw**，或返回错误让连接失败，**绝不**发"标 Zlib 装原始字节"的 rect。**验收**：注入 zlib 失败的测试断言编码一致性。
- **CORR-2**：`prevButtonMask`/`sasCtrl`/`sasAlt` 从包级全局挪到 `session` 结构体。**验收**：双并发连接输入状态隔离测试。
- **CORR-3**：`staticFrames` 的 dirty 判断移入 `c.mu` 临界区。**验收**：`-race` 通过。
- **CORR-4**：未知客户端消息类型按 RFB 规范**跳过并记日志**，不断连；需先读完整条消息体再丢弃（维护读写位置一致）——对未知类型无法预知长度时，按规范断开是允许的，需在实现中区分"未知类型"与"已知但超长"。
- **CORR-5**：分辨率变化时发 `DesktopSize(-223)` 伪矩形；可选 Cursor(-239)。**验收**：切桌面分辨率后客户端自动 rescale。
- **依赖**：Phase 0。

### Phase 3 — 可靠性与安全卫生（M2，原 OPSEC 退化版）· OPS-1..3, PERF-1..3, FUNC-1
- **OPS-1 UPX**：改为可选（默认关），Makefile `USE_UPX=1` 才压缩；文档说明签名影响。
- **OPS-2 服务名**：ServerInit name 改为可配置（默认 `"TailVNC"`），**不随机化**。
- **OPS-3 端口/私钥**：本地 agent 端口随机化（减少本地攻击面可预测性）；tsnet 状态目录加 ACL（仅 SYSTEM/Admins），评估私钥落盘加密。
- **PERF-1 全动态帧率**：把"需全量更新"与"静态"状态分离，全动态内容给全帧速率设上限（如 15fps），不再无脑 30fps。
- **PERF-2 捕获分配**：帧缓冲池化（双缓冲复用）；消除捕获侧标量循环——直接采集成编码器消费的像素格式，或把 BGRA→RGBA 交换下沉到 fast-path。
- **PERF-3 剪贴板**：仅在有订阅者时轮询并退避；优先改用 `AddClipboardFormatListener`（事件驱动）替代 500ms 轮询。
- **FUNC-1 剪贴板编码**：支持 UTF-8 / UTF-16 透传（RFB 剪贴板扩展或双向 UTF-8），保留 Latin-1 回退。

### Phase 4 — 运维/生命周期（M3）· LIFE-1..4
- **LIFE-1 日志**：重新启用文件日志，路径可配（默认 `%ProgramData%\TailVNC\logs\`），service/agent 各一份，带轮转。
- **LIFE-2 优雅退出**：引入 `context.Context` 贯穿；信号处理；Accept 循环与 capture loop 可取消；deferred 资源释放。
- **LIFE-3 端口冲突**：启动检测端口占用 + 指数退避重生 + 单实例识别，消除 flapping。
- **LIFE-4 背压/限速**：FBU 请求限速（每客户端 QPS 上限）；单 writer goroutine + channel 替代单 `writeMu`；代理 goroutine 有界 + 超时。

### Phase 5 — 持久化（M3）· OPS-4（合法运维核心特性）
- **新增 `tailvnc --install [--config-dir] [--listen-port] [--auth-pass-env]`**：
  - 必须提权（否则清晰报错退出）；写 Windows 事件日志。
  - 拷贝二进制到 `%ProgramFiles%\TailVNC\TailVNC.exe`（受保护 ACL → SEC-4）。
  - 注册 SCM 服务 `TailVNC`（自启 + 失败重启策略，LocalSystem）。
  - 配置/日志/状态放 `%ProgramData%\TailVNC\`，ACL 仅 SYSTEM/Admins（→ OPS-3, LIFE-1）。
- **`tailvnc --uninstall`**：停服 + 删服，可选清文件。
- **密钥/密码**：服务启动从受保护配置读，不 baked-in、不进命令行（→ SEC-6）。
- **保留**现有 Session 0 自动检测（SCM 起服务时自然走 `RunAsService`）。
- **显式不做**：Run key / WMI / 隐蔽计划任务。合法持久化 = SCM 且对 `services.msc` 可见。
- **验收**：`sc query TailVNC` 可见；重启后服务自起；非提权安装被拒；卸载干净。
- **授权语境**：README 与 `--help` 明确"仅供合法远程运维，需目标机管理员授权"。

### Phase 6 — 质量/文档（M3）· QUAL-1..5, DOC-1
- **QUAL-1**：清理 4 处 vet 误报（用安全 API 替代 `*[1<<28]uint64` trick 等）。
- **QUAL-2**：`obfuscateKey` 抽共享常量。
- **QUAL-3**：改用标准 `flag` 包（或保留但补 `--flag=val`/`--help`/未知参数报错）。
- **QUAL-4**：`des.NewCipher` 错误显式处理。
- **QUAL-5**：`winInput` 用 `unsafe.Sizeof`/`alignof` 推导 padding，移除写死 `[4]byte`。
- **DOC-1**：修 README XOR/AES 与持久化措辞；dual-use 改为合法运维为主；加 LICENSE（建议 MIT/Apache-2.0）。

---

## 7. 测试策略
- **单元**：纯逻辑层表驱动（Phase 0），目标 ≥80%。
- **集成**：loopback RFB（server + 极简 client）覆盖握手/VNCAuth 成败/FBU 全量与脏/伪编码。
- **并发**：`go test -race` 覆盖 CORR-2/CORR-3。
- **构建矩阵**：CI 同时跑 `GOOS=linux go test ./...`（纯逻辑）与 `GOOS=windows go vet ./...`。
- **安全**：SEC-2/SEC-4 的拒绝路径各一个测试；VNCAuth 失败计数测试。

---

## 8. 风险与回滚
- 每里程碑独立 PR，可单独回滚。
- Phase 1 认证变更（尤其 VeNCrypt）是最大兼容性风险 → 默认先用"失败计数+退避+默认 127.0.0.1"，VeNCrypt 作可选项。
- 拆 build tag（Phase 0）若漏改会导致 Windows 编译失败 → CI 必须 `GOOS=windows go build`。
- agent 权限收敛（SEC-5）可能影响安全桌面捕获 → 需回归测试 Winlogon/UAC 桌面。

---

## 9. 开放问题（留 writing-plans / 实施时决策）
1. **VeNCrypt/TLS 是否进 M1？** 建议：M1 先做"失败计数+退避+默认 loopback"，VeNCrypt 列为 M1 可选 stretch，避免认证重写拖慢安全兜底。
2. **IPC 通道**：named pipe + DACL vs loopback TCP + token？倾向 named pipe（更符合 Windows 原生安全模型），但增加实现复杂度。
3. **私钥落盘加密**：用 DPAPI（`CryptProtectData`）保护 tsnet 状态？需评估 tsnet 自身状态加载兼容性。
4. **剪贴板 FUNC-1**：走 RFB 剪贴板 UTF-8 扩展还是双向转码？需确认主流客户端支持情况。
