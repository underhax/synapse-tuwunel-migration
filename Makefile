VERSION ?= dev
TARGET ?= ./...

.PHONY: check lint test coverage vulncheck trivy secrets-scan verify build clean

lint:
	golangci-lint run $(TARGET)

check:
	@test -z "$$(gofmt -s -l .)" || (echo "Unformatted files found. Run 'gofmt -s -w .' to fix them." && false)
	golangci-lint run ./...
	CGO_ENABLED=0 go build -tags goolm ./...

test:
	CGO_ENABLED=0 go test -tags goolm -v -race ./...

coverage:
	CGO_ENABLED=0 go test -tags goolm -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vulncheck:
	govulncheck -tags goolm ./...

trivy:
	trivy fs --severity CRITICAL,HIGH .

secrets-scan:
	gitleaks detect --source . --no-git --no-color --verbose

verify: check test vulncheck trivy secrets-scan

build:
	CGO_ENABLED=0 go build -trimpath -tags goolm -ldflags "-s -w -X main.AppVersion=$(VERSION)" -o migrator ./cmd/migrator

clean:
	rm -rf coverage coverage.out
