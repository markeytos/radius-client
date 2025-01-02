GO_DIRS=$(shell find . -type d)
GO_FILES=$(shell find . -type f -name '*.go')

./bin/radius-client: $(GO_DIRS) $(GO_FILES)
	@mkdir -p bin
	go build -o ./bin/radius-client

checks:
	go fmt ./...
	go vet ./...
	go mod tidy
	golangci-lint run

clean:
	rm -rf bin
