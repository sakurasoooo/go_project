.PHONY: build test smoke integration

build:
	mkdir -p bin
	go build -o bin/survey ./cmd/survey

test:
	go test ./cmd/... ./internal/...

smoke: build
	bash scripts/smoke.sh

# SMK-10 / SMK-11 — local UDP stub + CLI (opt-in for CI via workflow).
integration:
	go test ./cmd/survey -tags=integration -count=1 -timeout 3m
