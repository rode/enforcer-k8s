# syntax = docker/dockerfile:experimental
FROM golang:1.17 as builder

WORKDIR /workspace
COPY go.mod go.sum /workspace/
RUN go mod download

COPY main.go main.go
COPY config config
COPY enforcer enforcer

RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o enforcer-k8s

# ---------------

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source=https://github.com/rode/enforcer-k8s

WORKDIR /
COPY --from=builder /workspace/enforcer-k8s .

USER nonroot:nonroot

ENTRYPOINT ["./enforcer-k8s"]
