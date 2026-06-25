VERSION     	?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME  	= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
AUTH_KEY    	?=
CONTROL_URL 	?=
LDFLAGS     	= -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)$(if $(AUTH_KEY), -X main.buildWithObfuscatedAuthKey=$(shell AUTH_KEY='$(AUTH_KEY)' go run obfuscator/obfuscate_key_hex.go))$(if $(CONFIG_DIR), -X main.buildWithConfigDir=$(CONFIG_DIR))$(if $(CONTROL_URL), -X main.buildWithControlURL=$(CONTROL_URL))$(if $(LISTEN_PORT), -X main.buildWithListenPort=$(LISTEN_PORT))$(if $(AUTH_PASS), -X main.buildWithAuthPass=$(AUTH_PASS))$(if $(LISTEN_ADDR), -X main.buildWithListenAddr=$(LISTEN_ADDR))"
BUILD_ENV   	= CGO_ENABLED=0
BUILD_PACKAGE	?=
BINARY_NAME 	?=

# Default suffix: build timestamp to the minute (UTC), e.g. _20260625_1755.
# Override with BIN_SUFFIX= to drop it (e.g. for CI reproducible builds).
BIN_SUFFIX 	?= _$(shell date -u '+%Y%m%d_%H%M')

PLATFORMS = \
	windows/amd64

# Default target
.PHONY: all
all: clean build

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf dist/
	go clean

# Build for current platform
.PHONY: build
build:
	$(BUILD_ENV) go build $(LDFLAGS) -o $(BINARY_NAME) .

# Install dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

# Build for a specific platform
.PHONY: build-platform
build-platform:
	@mkdir -p dist
	@os=$(word 1, $(subst /, ,$(PLATFORM))); \
	arch=$(word 2, $(subst /, ,$(PLATFORM))); \
	ext=$$( [ $$os = windows ] && echo .exe || echo ); \
	out=dist/$(BINARY_NAME)-$$os-$$arch$$ext; \
	echo "Building $$os/$$arch -> $$out"; \
	GOOS=$$os GOARCH=$$arch $(BUILD_ENV) go build $(LDFLAGS) -o $$out $(BUILD_PACKAGE); \
	[ -x "$$(command -v upx)" ] && upx --best --lzma $$out || true

# Build vnc with windows platforms
.PHONY: build-vnc
build-vnc: clean deps
	@$(foreach platform, $(PLATFORMS), \
		$(MAKE) build-platform PLATFORM=$(platform) AUTH_KEY="$(AUTH_KEY)" CONFIG_DIR="$(CONFIG_DIR)" CONTROL_URL="$(CONTROL_URL)" LISTEN_PORT="$(LISTEN_PORT)" AUTH_PASS="$(AUTH_PASS)" BUILD_PACKAGE="tailvnc/cmd/vnc" BINARY_NAME="TailVNC$(BIN_SUFFIX)";)


# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build-vnc				   - Build vnc server for all platforms"
	@echo "  help                      - Show this help"
	@echo ""
	@echo "Parameters (all optional; no AUTH_KEY = plain VNC over TCP):"
	@echo "  AUTH_KEY                  - Tailscale auth key; embeds a WireGuard peer (tsnet)."
	@echo "                               Omit to serve plain VNC over TCP without Tailscale."
	@echo "  LISTEN_ADDR               - Bind address for direct/TCP mode (default: 0.0.0.0)"
	@echo "  LISTEN_PORT               - VNC listen port (default: 5900)"
	@echo "  AUTH_PASS                 - VNC password baked in at build time (optional; see runtime override)"
	@echo "  CONTROL_URL               - Headscale control server URL (tsnet only)"
	@echo "  CONFIG_DIR                - tsnet persistent state dir (default: C:\\Windows\\Temp\\.config)"
	@echo ""
	@echo "Runtime flags (override build-time values; --auth-pass is mandatory):"
	@echo "  --auth-key <key>          - Tailscale auth key (overrides AUTH_KEY; omit for direct TCP)"
	@echo "  --auth-pass <pwd>         - VNC password (overrides AUTH_PASS; REQUIRED if not baked in)"
	@echo ""
	@echo "Examples:"
	@echo "  # Plain VNC over TCP (no Tailscale):"
	@echo "  make build-vnc LISTEN_PORT=5900 AUTH_PASS=Passw0rd"
	@echo ""
	@echo "  # VNC over Tailscale (embedded WireGuard):"
	@echo "  make build-vnc AUTH_KEY=tskey-auth-xxxxxx LISTEN_PORT=5900 AUTH_PASS=Passw0rd"