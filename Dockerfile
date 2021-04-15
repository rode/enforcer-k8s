# syntax = docker/dockerfile:experimental
FROM golang:1.15 as builder

WORKDIR /workspace
COPY go.mod go.sum /workspace/
RUN go mod download

COPY main.go main.go
COPY certs certs

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o enforcer-k8s

ENTRYPOINT ["./enforcer-k8s"]
