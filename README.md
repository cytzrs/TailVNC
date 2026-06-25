# TailVNC

A Windows remote desktop persistence tool built on top of Tailscale's WireGuard-encrypted mesh network. TailVNC embeds a fully self-contained VNC server and Tailscale node into a single binary, enabling secure remote desktop access over Tailscale/Headscale without exposing any ports to the public internet. Designed for both legitimate infrastructure administration and red team persistence operations.

Inspired by [SockTail](https://github.com/Yeeb1/SockTail).

## Features

- **Tailscale/Headscale Integration** - Leverages `tsnet` to embed a WireGuard peer directly into the binary; supports both official Tailscale coordination and self-hosted Headscale control planes
- **Windows Session 0 Isolation Bypass** - When running as SYSTEM, automatically spawns an agent process in the active user session via `CreateProcessAsUser` and proxies VNC traffic through IPC, circumventing Vista+ session isolation
- **Dynamic Desktop Tracking** - Follows the user across desktop transitions including the default desktop, Winlogon (login screen), UAC secure desktop, and lock screen via `OpenInputDesktop`/`SetThreadDesktop`
- **Ctrl+Alt+Del Injection** - Sends the Secure Attention Sequence from Session 0 via `sas.dll!SendSAS`
- **Bidirectional Clipboard Sync** - Latin-1 clipboard synchronization between VNC client and target host
- **Build-Time Configuration Embedding** - Auth key, VNC password, listen port, and control URL are injected at compile time via LDFLAGS; the resulting binary requires no configuration files at runtime
- **Auth Key Obfuscation** - Tailscale auth key is XOR-obfuscated at build time to prevent plaintext credential exposure in the binary

## Architecture

```
┌──────────────────────────────────────────────┐
│          TailVNC Service (Session 0)         │
│                                              │
│  tsnet.Server ───► Tailscale/Headscale Net   │
│       │                                      │
│  VNC Listener :5900 (Tailscale interface)    │
│       │                                      │
│  ┌────▼───────────────────────────────────┐  │
│  │ Session Manager                        │  │
│  │  - Polls active console session (2s)   │  │
│  │  - Spawns agent via CreateProcessAsUser│  │
│  │  - Auto-restarts on session change     │  │
│  │    or agent crash                      │  │
│  └────┬───────────────────────────────────┘  │
│       │ TCP Proxy (bidirectional)            │
└───────┼──────────────────────────────────────┘
        ▼
┌────────────────────────────────────────┐
│   VNC Agent (User Session, Desktop)    │
│   127.0.0.1:15900                      │
│   - GDI+ screen capture (~30fps)       │
│   - SendInput keyboard/mouse injection │
│   - Clipboard monitoring               │
└────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.25+ |
| Network Transport | [Tailscale tsnet](https://pkg.go.dev/tailscale.com/tsnet) (optional, embedded WireGuard) or plain TCP |
| VNC Protocol | RFB 3.008 (custom implementation, Raw encoding) |
| Screen Capture | Windows GDI+ (`CreateDIBSection`, `BitBlt`) |
| Input Injection | Windows `SendInput` API |
| Session Management | `WTSQueryUserToken` + `CreateProcessAsUser` |
| Desktop Switching | `OpenInputDesktop` + `SetThreadDesktop` |
| SAS Injection | `sas.dll!SendSAS` |
| Authentication | VNC DES challenge-response (per RFB spec) |
| Key Obfuscation | AES-256-CTR + hex encoding |
| System Calls | `golang.org/x/sys` (Windows syscall wrappers) |
| Binary Compression | UPX (optional) |
| Build System | GNU Make + Go LDFLAGS injection |

## Building

### Prerequisites

- **Go** >= 1.25.3
- **GNU Make**
- **UPX** (optional, for binary size reduction)
- **Tailscale Auth Key** *(optional)* — only required to embed a WireGuard peer (tsnet). Omit to serve plain VNC over TCP.

### Build Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `AUTH_KEY` | No | Empty (plain TCP) | Tailscale auth key baked in at build time; when set, embeds a WireGuard peer (tsnet). Omit for plain VNC over TCP. Can be overridden at runtime via `--auth-key`. |
| `LISTEN_ADDR` | No | `0.0.0.0` | Bind address for direct/TCP mode (ignored in tsnet mode) |
| `LISTEN_PORT` | No | `5900` | VNC listen port |
| `AUTH_PASS` | No | Empty (build-time default) | VNC password baked in at build time (DES challenge-response). Can be overridden at runtime via `--auth-pass`; **a password is mandatory** — the binary refuses to start if none is provided at runtime or build time. |
| `CONTROL_URL` | No | Empty (official Tailscale) | Headscale control plane URL (tsnet only) |
| `CONFIG_DIR` | No | `C:\Windows\Temp\.config` | Persistent tsnet state directory (WireGuard keys, node identity) |

### Compilation

```bash
# Default build — plain VNC over TCP, no Tailscale dependency
# AUTH_PASS here is just a build-time default; pass --auth-pass at runtime to override
make build-vnc LISTEN_PORT=5900 AUTH_PASS=VNCPassword

# Tailscale build — embeds a WireGuard peer via tsnet
# [CONTROL_URL] — optional, only required when using a self-hosted Headscale control plane
# [CONFIG_DIR]  — optional, overrides the default tsnet state directory (C:\Windows\Temp\.config)
make build-vnc \
  AUTH_KEY=tskey-auth-kBEXAMPLEKEY \
  LISTEN_PORT=5900 \
  AUTH_PASS=VNCPassword \
  [CONTROL_URL=https://headscale.example.com] \
  [CONFIG_DIR='C:\Windows\Temp\.config']
```

Build artifacts are written to `dist/`:

```
dist/TailVNC-windows-amd64.exe
```

The build pipeline performs the following steps:

1. Cleans previous build artifacts
2. Downloads and tidies Go module dependencies
3. Runs `obfuscator/` to AES-encrypt the auth key (when `AUTH_KEY` is set)
4. Injects all configuration into the binary via LDFLAGS (`-X`)
5. Strips the symbol table and DWARF debug info (`-s -w`)
6. Compresses the binary with UPX (`--best --lzma`) if available

### Additional Make Targets

```bash
make clean    # Remove build artifacts
make deps     # Download and tidy Go modules
make help     # Print usage and parameter reference
```

## Usage

**TailVNC must run with SYSTEM privileges.** When executing in Session 0 (as a Windows service or under SYSTEM context), the tool automatically detects the active console session, spawns an agent process within it for screen capture and input injection, and proxies all VNC traffic. If launched directly within an interactive user session, it operates in local mode without the agent proxy layer.

**Runtime flags** override the build-time defaults and take priority:

- `--auth-key <key>` — Tailscale auth key (overrides `AUTH_KEY`; omit for direct TCP)
- `--auth-pass <pwd>` — VNC password (overrides `AUTH_PASS`; **required** if not baked in)

```bash
# Run with a runtime password (no build-time default needed)
TailVNC.exe --auth-pass VNCPassword

# Run over Tailscale with a runtime auth key
TailVNC.exe --auth-key tskey-auth-xxxxxx --auth-pass VNCPassword
```

If neither a runtime `--auth-pass` nor a build-time `AUTH_PASS` is provided, the binary refuses to start.

Depending on the build mode, connect using any standard VNC client:

- **Tailscale build** (with `AUTH_KEY`): the target host joins the configured Tailscale network as a new node.

  ```
  <Tailscale IP>:5900
  ```

- **Direct/TCP build** (without `AUTH_KEY`): the server listens on `LISTEN_ADDR:LISTEN_PORT` (default `0.0.0.0:5900`).

  ```
  <target IP>:5900
  ```

![image-20260412003923140](assets/image-20260412003923140.png)

![image-20260412004037568](assets/image-20260412004037568.png)
