.PHONY: test fmtcheck vet fmt coverage mocks
GOFMT_FILES?=$$(find . -name '*.go')

GO111MODULE=on

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

fmt:
	gofmt -w -s $(GOFMT_FILES)

mocks:
	go install github.com/golang/mock/mockgen@v1.5.0
	go generate ./...

vet:
	go vet ./...

test: fmtcheck vet
	go test ./... -coverprofile=coverage.txt -covermode atomic

coverage: test
	go tool cover -html=coverage.txt
