./bin/radius-client: ./radius/*.go
	@mkdir -p bin
	go build -o ./bin/radius-client

checks:
	go fmt ./...
	go vet ./...
	go mod tidy
	golangci-lint run

clean:
	rm -rf bin
