# TailVNC 变更记录

对比基准：`master` 分支 (`2abf898 Add image`)
生成时间：2026-06-25

本次变更包含两大类工作：**代码审查修复（6 项 bug + 1 项性能优化）** 和 **tsnet 嵌入可选化改造**。

---

## 功能变更（Features）

### tsnet / WireGuard 嵌入改为可选，默认不嵌入

将 Tailscale WireGuard 嵌入从强制依赖改为**可选**，默认关闭。构建时不提供 `AUTH_KEY` 即生成纯 TCP VNC 服务端，无需任何 Tailscale 依赖。

**动机**：原实现强制要求 `AUTH_KEY`（缺省则 `exit 1`），无法作为标准 VNC-over-TCP 服务使用。改为可选后，同一份代码兼顾两种部署形态。

**行为**
- `AUTH_KEY` 为空（默认）：`net.Listen("tcp", "LISTEN_ADDR:port")` 直接监听标准 VNC over TCP，不启动 tsnet
- `AUTH_KEY` 非空：走原 tsnet 路径，嵌入 WireGuard peer，VNC 流量经 Tailscale/Headscale mesh 加密传输
- 两条路径共享新提取的 `serve()` 函数（按 Windows Session ID 分流 service/agent 模式），消除重复逻辑

**涉及文件**
- `cmd/vnc/main.go`：新增 `startDirectServer()`、`serve()` 共享入口、`buildWithListenAddr` 构建变量；移除 `else { return }` 早退（此前使直接模式无法启动）
- `Makefile`：移除 `AUTH_KEY` 必填校验；新增 `LISTEN_ADDR` 注入
- `README.md`：技术栈表、构建参数表、示例、Usage 段全部同步更新

**新增构建参数**

| 参数 | 默认 | 说明 |
|------|------|------|
| `LISTEN_ADDR` | `0.0.0.0` | 直接/TCP 模式绑定地址（tsnet 模式忽略） |

**构建示例**
```bash
# 纯 TCP（默认，无需任何 key）
make build-vnc LISTEN_PORT=5900 AUTH_PASS=Passw0rd

# Tailscale（加 AUTH_KEY 启用 WireGuard）
make build-vnc AUTH_KEY=tskey-auth-xxxxxx LISTEN_PORT=5900 AUTH_PASS=Passw0rd
```

---

## Bug 修复（Bug Fixes）

### [P0] 扩展键 KEYEVENTF 标志用错，方向键/导航键注入异常 — Bug 1 + 7

`SimulateKeyEvent` 对扩展键（方向键、Insert/Delete、Home/End、PageUp/Down）设置的标志错误：
常量 `extendedKeyFlag` 值为 `0xe000`（错误，应为标准 `KEYEVENTF_EXTENDEDKEY` `0x0001`），且 `SimulateKeyEvent` 误用了 `keyeventfScanCode` (`0x0008`) 而非 `extendedKeyFlag`。`extendedKeyFlag` 常量此前从未被引用。

**修复**：`extendedKeyFlag` 改为 `0x0001`；`SimulateKeyEvent` 改用 `extendedKeyFlag`。

**文件**：`pkg/vnc/input.go`

### [P0] 空密码下 VNCAuth 静默放行任意客户端 — Bug 3

`doVNCAuth` 在 `s.password == ""` 时跳过 DES 比对，`result` 恒为 0，导致选择 VNCAuth 安全类型的客户端无需正确响应即可通过认证（认证绕过）。正常握手虽不会进入此分支，但属于防御性编码缺陷。

**修复**：`doVNCAuth` 前置守卫——`password == ""` 时直接 `return error`，拒绝认证；移除冗余的 `if s.password != ""` 包裹，使 DES 比对无条件执行。

**文件**：`pkg/vnc/rfb.go`

### [P1] 分辨率动态变化导致输入坐标错位 — Bug 4

`session.serverW/serverH` 在会话创建时一次性快照，永不更新。但 `SessionAwareCapturer` 会随桌面切换（Winlogon/UAC 安全桌面常为不同分辨率）动态更新 `Width()/Height()`，导致：
- `handlePointerEvent` 用陈旧 `serverW` 归一化坐标 → 鼠标系统性偏移
- `sendFramebufferUpdate` 的 clamp 用陈旧边界 → 帧裁剪错误

**修复**：新增 `session.syncDims()` 方法，在 `handleFBUpdateRequest` 和 `handlePointerEvent` 入口实时从 capturer 同步 `serverW/serverH`。

**文件**：`pkg/vnc/rfb.go`

### [P2] auth key 混淆强度不足，明文 XOR key 暴露在仓库内 — Bug 10

原实现用硬编码 XOR key `r4!kV#9xLp`（仓库内明文可见）混淆 auth key，`strings`/hex dump/逆向即可还原，仅能挡住最粗心的分析，README 却宣称 "prevent plaintext credential exposure"。

**修复**：改为 **AES-256-CTR** 加密。构建时生成随机 nonce，输出 `hex(nonce ‖ ciphertext)`；运行时按相同布局解密。移除仓库内明文 key。AES key 仍嵌入二进制（单机植入对称加密的固有限制），但加密算法 + 每构建随机 nonce 使静态分析门槛大幅提高。

**文件**：`obfuscator/obfuscate_key_hex.go`、`pkg/deobfuscator/deobfuscate_key_hex.go`
**验证**：往返测试通过（加密→解密正确还原原文）

### [P2] SetCursorPos 与 SendInput 冗余调用 — Bug 9

`SimulatePointer` 先调用 `SetCursorPos(x,y)`（不经输入流，全屏应用/游戏会忽略），再调用 `sendMouseInput(Move|Absolute)`（标准方式，已含绝对坐标），两者重复。且 `absX/absY` 被计算两次并用 `_ =` 丢弃。

**修复**：移除冗余 `SetCursorPos`，单次 `sendMouseInput` 调用复用已计算的 `absX/absY`；顺手移除变成死代码的 `procSetCursorPos`、`procGetCursorPos` 声明。

**文件**：`pkg/vnc/input.go`

### [Bug] Makefile 死变量与 LISTEN_PORT 门控错误

LDFLAGS 中 `LISTEN_PORT` 被无关变量 `SOCKS5_PORT` 错误门控（传 `LISTEN_PORT` 但不传 `SOCKS5_PORT` 时不生效），且存在死变量 `EXPOSE_DIR` / `buildWithExposeDir`（泄漏自其他项目模板）。

**修复**：移除 `SOCKS5_PORT`/`EXPOSE_DIR` 死变量，`LISTEN_PORT` 直接用自身门控。

**文件**：`Makefile`

---

## 性能优化（Performance）

### 帧编码逐像素循环优化 — Bug 8

`sendFramebufferUpdate` 此前对每帧逐像素执行 Go 循环（4K 屏 ~800 万次迭代/帧），含乘法/移位/字节序处理，且忽略 `incremental` 标志每次发全屏，CPU 与 GC 压力大。

**优化**：拆分为两条路径
- **快速路径** `encodePixelsFast`：客户端使用标准 32bpp RGB-255（shift 16/8/0，几乎所有真实 VNC viewer 默认）时启用——按行处理，大端/小端各自做单次内存布局转换，消除逐像素运算
- **通用路径** `encodePixelsGeneric`：非标准格式（低色深、非 255 max、异常 shift）走原逻辑保证正确性
- 新增 `canUseFastPath()` 分派器

**文件**：`pkg/vnc/rfb.go`
**验证**：对比测试确认 fast path 与 generic path 在大端、小端两种字节序下输出逐字节一致

---

## 文档（Documentation）

- `README.md` 全文同步：
  - 技术栈表 Network Transport 改为 "tsnet (optional) or plain TCP"
  - Key Obfuscation 描述从 "XOR" 更新为 "AES-256-CTR"
  - 构建参数表 `AUTH_KEY` 改可选、新增 `LISTEN_ADDR`
  - 构建示例补充纯 TCP 模式
  - Usage 段补充直接模式连接方式
- `Makefile` `help` target 输出更新：参数全部可选，给出两种构建示例

---

## 经评估未改（保留的设计取舍）

以下问题经评估属合理设计或风险大于收益，本轮不改：

| 项 | 评估结论 |
|----|----------|
| Bug 2 `setupInteractiveWindowStation` 未调用 | 设计意图——截屏实际在 agent 进程（非 service）执行，继承用户会话 WinSta0，恰好能工作。仅注释误导，改代码无收益 |
| Bug 5 SAS 非重入 | `WaitForSingleObject(INFINITE)` + auto-reset 事件合并连续 Ctrl+Alt+Del 信号，连按本身罕见，合并是合理行为，改异步徒增复杂度与竞态 |
| Bug 6 桌面过渡无心跳 | 桌面切换失败时保留旧帧（冻结画面）是优于断连的合理降级，RFB 协议无标准心跳，强行加通知会引入帧抖动 |

---

## 文件变更统计

```
 Makefile                                |  26 ++++-----
 README.md                               |  43 ++++++++------
 cmd/vnc/main.go                         |  49 ++++++++++++++--
 obfuscator/obfuscate_key_hex.go         |  34 +++++++++--
 pkg/deobfuscator/deobfuscate_key_hex.go |  32 ++++++++--
 pkg/vnc/input.go                        |  21 +++----
 pkg/vnc/rfb.go                          | 100 ++++++++++++++++++++++++++------
 7 files changed, 230 insertions(+), 75 deletions(-)
```
