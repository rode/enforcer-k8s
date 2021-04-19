# syntax = docker/dockerfile:experimental
FROM golang:1.16 as builder

WORKDIR /workspace
COPY go.mod go.sum /workspace/
RUN go mod download

COPY main.go main.go
COPY config config

RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o enforcer-k8s

# ---------------

FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /workspace/enforcer-k8s .

USER nonroot:nonroot

ENTRYPOINT ["./enforcer-k8s"]
