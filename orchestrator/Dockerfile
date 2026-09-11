FROM golang:1.23-alpine AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/orchestrator ./cmd/orchestrator

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl bind-tools
# Security-tool binaries are mounted or installed into this dir at deploy time.
ENV ARGUS_TOOLS_BIN_DIR=/usr/local/bin
COPY --from=build /out/orchestrator /usr/local/bin/orchestrator
RUN adduser -D argus
USER argus
ENTRYPOINT ["/usr/local/bin/orchestrator"]
