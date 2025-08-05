DEFAULT_TEST_ARGS = -v -timeout 300s

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