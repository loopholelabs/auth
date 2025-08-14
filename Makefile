DEFAULT_TEST_ARGS = -v -timeout 1800s -tags=test
BUILD_DOCKER_IMAGE = auth-build:local
RUN_DOCKER_IMAGE = auth:local
BUILD_GIT_COMMIT = $(shell git rev-parse --short HEAD)
BUILD_GO_VERSION = $(shell (go version | awk '{print $$3}'))
BUILD_DATE=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
BUILD_PLATFORM = $(shell (go version | awk '{print $$4}'))
BUILD_VERSION = $(shell git rev-parse --short HEAD)
DEFAULT_BUILD_ARGS = -ldflags='-s -w -X github.com/loopholelabs/auth/version.GitCommit=$(BUILD_GIT_COMMIT) -X github.com/loopholelabs/auth/version.GoVersion=$(BUILD_GO_VERSION) -X github.com/loopholelabs/auth/version.BuildDate=$(BUILD_DATE) -X github.com/loopholelabs/auth/version.Platform=$(BUILD_PLATFORM) -X github.com/loopholelabs/auth/version.Version=$(BUILD_VERSION)' -trimpath

.PHONY: build-image
build-image:
	 docker build --tag $(BUILD_DOCKER_IMAGE) . -f build.Dockerfile

.PHONY: run-image
run-image:
	 docker build --tag $(RUN_DOCKER_IMAGE) . -f run.Dockerfile

.PHONY: generate
generate:
	go generate ./...

.PHONY: test
test: generate
	go test $(DEFAULT_TEST_ARGS) ./...

.PHONY: test-specific
test-specific: generate
	go test $(DEFAULT_TEST_ARGS) $(TEST_ARGS)

.PHONY: lint
lint: generate
	GOOS=linux golangci-lint run --fix ./...

.PHONY: build
build: generate
	docker run --rm -v .:/root/auth $(BUILD_DOCKER_IMAGE) bash -c "go build $(DEFAULT_BUILD_ARGS) -o build/auth cmd/main.go"
