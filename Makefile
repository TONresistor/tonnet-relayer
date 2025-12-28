.PHONY: build build-all clean deps test lint

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/tonnet-relay ./cmd/

build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-relay-linux-amd64 ./cmd/
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/tonnet-relay-linux-arm64 ./cmd/
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-relay-darwin-amd64 ./cmd/
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/tonnet-relay-darwin-arm64 ./cmd/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-relay-windows-amd64.exe ./cmd/

clean:
	rm -rf bin/

deps:
	go mod download
	go mod tidy

test:
	go test -v ./...

lint:
	golangci-lint run
