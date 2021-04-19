.PHONY: test fmtcheck vet fmt coverage
GOFMT_FILES?=$$(find . -name '*.go' | grep -v proto)

GO111MODULE=on

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

fmt:
	gofmt -w -s $(GOFMT_FILES)

vet:
	go vet ./...

test: fmtcheck vet
	go test ./... -coverprofile=coverage.txt -covermode atomic

coverage: test
	go tool cover -html=coverage.txt
