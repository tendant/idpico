# Build on the host platform and cross-compile for the target (pure Go, no
# cgo), so multi-platform builds do not emulate the Go toolchain.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /idpico ./cmd/idpico \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /idpicoctl ./cmd/idpicoctl

FROM alpine:3.19
RUN apk --no-cache add ca-certificates \
 && addgroup -S -g 10001 idp && adduser -S -u 10001 -G idp idp
WORKDIR /app
COPY --from=builder /idpico /idpicoctl ./
RUN mkdir -p /app/data && chown -R idp:idp /app
USER idp
EXPOSE 8080
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["./idpico"]
