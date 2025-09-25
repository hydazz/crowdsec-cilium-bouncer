APP_BIN ?= bin/crowdsec-cilium-bouncer

.PHONY: build test fmt tidy clean

build: ## Build the bouncer binary
	go build -o $(APP_BIN) ./cmd

test: ## Run unit tests
	go test ./...

fmt: ## Format Go source files
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

tidy: ## Ensure go.mod and go.sum are tidy
	go mod tidy

clean: ## Remove build artefacts
	rm -f $(APP_BIN)
