.PHONY: all build test lint fmt clean help

# Build settings
BINARY_NAME := aggregate-cidr
GO := go
GOFLAGS := -ldflags="-s -w"

# Default target
all: lint test build

## Build the binary
build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

## Run tests
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

## Run tests with coverage report
coverage: test
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## Run linter
lint:
	golangci-lint run ./...

## Format code
fmt:
	$(GO) fmt ./...
	goimports -w .

## Clean build artifacts
clean:
	rm -f $(BINARY_NAME) coverage.out coverage.html
	$(GO) clean

## Install development tools
tools:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/cmd/goimports@latest

## Show help
help:
	@echo "Available targets:"
	@echo "  all       - Run lint, test, and build (default)"
	@echo "  build     - Build the binary"
	@echo "  test      - Run tests with race detection"
	@echo "  coverage  - Generate HTML coverage report"
	@echo "  lint      - Run golangci-lint"
	@echo "  fmt       - Format code with gofmt and goimports"
	@echo "  clean     - Remove build artifacts"
	@echo "  tools     - Install development tools"
	@echo "  help      - Show this help message"
