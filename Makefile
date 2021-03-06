.PHONY: test fmtcheck vet fmt coverage mocks license
GOFMT_FILES?=$$(find . -name '*.go')
GO111MODULE=on

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

fmt:
	gofmt -w -s $(GOFMT_FILES)

license:
	addlicense -c 'The Rode Authors' $(GOFMT_FILES)

vet:
	go vet ./...

test: fmtcheck vet
	go test ./... -coverprofile=coverage.txt -covermode atomic

coverage: test
	go tool cover -html=coverage.txt
