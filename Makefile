GO ?= go
GOFLAGS ?=
BINARY ?= bin/owfuzz

.PHONY: all build test race vet parity cross legacy clean
all: build
build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/owfuzz

test:
	CGO_ENABLED=0 $(GO) test $(GOFLAGS) ./...
race:
	CGO_ENABLED=1 $(GO) test $(GOFLAGS) -race ./...
vet:
	CGO_ENABLED=0 $(GO) vet $(GOFLAGS) ./...
# Optional: the independently built C executable is used only as a test oracle.
parity:
	CGO_ENABLED=0 OWFUZZ_C_REFERENCE=$(CURDIR)/owfuzz/src/owfuzz $(GO) test -count=1 -run TestCNativeDifferential -v ./internal/app
cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o bin/owfuzz-linux-arm64 ./cmd/owfuzz
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build $(GOFLAGS) -o bin/owfuzz-linux-armv7 ./cmd/owfuzz
legacy:
	$(MAKE) -C owfuzz
clean:
	$(GO) clean ./...
