.PHONY: build install uninstall clean test bench run

# Build tags for gnet optimizations:
#   poll_opt - Optimized epoll/kqueue pollers (lower latency)
#   gc_opt   - Optimized connection matrix (less GC pressure)
TAGS := poll_opt,gc_opt

# Output binary
BINARY := telego

# Version info
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)

# Directory of this Makefile
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Install paths
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
SYSCONFDIR := /etc/telego
CONFIG := $(SYSCONFDIR)/config.toml

# Default target: build with all optimizations
build:
	CGO_ENABLED=0 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/telego

# Install as systemd service
install: build
	@echo "Installing $(BINARY) to $(BINDIR)..."
	install -d $(BINDIR)
	install -m 755 $(BINARY) $(BINDIR)/$(BINARY)
	@echo "Installing systemd service..."
	sed 's|CONFIG_PATH|$(CONFIG)|g' $(MAKEFILE_DIR)telego.service > /etc/systemd/system/telego.service
	systemctl daemon-reload
	@echo "Creating config directory..."
	install -d $(SYSCONFDIR)
	@if [ ! -f $(CONFIG) ]; then \
		echo "Installing example config to $(CONFIG)..."; \
		install -m 600 $(MAKEFILE_DIR)config.example.toml $(CONFIG); \
		echo "IMPORTANT: Edit $(CONFIG) and add your secrets"; \
	else \
		echo "Config already exists at $(CONFIG), skipping"; \
	fi
	@echo ""
	@echo "Installation complete. Next steps:"
	@echo "  1. Edit $(CONFIG)"
	@echo "  2. systemctl enable telego"
	@echo "  3. systemctl start telego"

# Uninstall
uninstall:
	systemctl stop telego 2>/dev/null || true
	systemctl disable telego 2>/dev/null || true
	rm -f /etc/systemd/system/telego.service
	rm -f $(BINDIR)/$(BINARY)
	systemctl daemon-reload
	@echo "Uninstalled. Config remains at $(SYSCONFDIR)"

# Run tests with optimizations
test:
	go test -tags="$(TAGS)" -race ./...

# Run benchmarks
bench:
	go test -tags="$(TAGS)" -bench=. -benchmem ./pkg/transport/...

# Run the proxy (development)
run: build
	./$(BINARY) run -c config.toml

# Build without optimizations (for debugging/profiling)
build-debug:
	go build -gcflags="all=-N -l" -o $(BINARY) ./cmd/telego

# Build for multiple platforms
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./cmd/telego

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(BINARY)-linux-arm64 ./cmd/telego

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-linux-*

# Format and lint
fmt:
	go fmt ./...
	go vet ./...

# Update dependencies
deps:
	go mod tidy
	go mod download
