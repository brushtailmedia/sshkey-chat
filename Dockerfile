# Build stage.
# Go 1.26-alpine floats to the latest 1.26.x point release. go.mod
# declares `go 1.26.2` (Phase 21 F2 bumped from 1.25 for 5 stdlib CVE
# fixes reached through archive/tar + crypto/tls/x509); the floating
# image tag stays current with future patch releases automatically.
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /sshkey-server ./cmd/sshkey-server
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /sshkey-ctl ./cmd/sshkey-ctl

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 2222 -S sshkey \
    && adduser -u 2222 -S -G sshkey -h /var/sshkey-chat sshkey

COPY --from=builder /sshkey-server /usr/local/bin/sshkey-server
COPY --from=builder /sshkey-ctl /usr/local/bin/sshkey-ctl

# Config and data directories
RUN mkdir -p /etc/sshkey-chat /var/sshkey-chat/data \
    /keys \
    && chown -R sshkey:sshkey /etc/sshkey-chat /var/sshkey-chat /keys

VOLUME ["/etc/sshkey-chat", "/var/sshkey-chat"]

EXPOSE 2222

USER sshkey

# WORKDIR is /var/sshkey-chat so bootstrap-admin without --out still
# writes to a persistent writable path. Docker docs prefer
# `bootstrap-admin --out /keys` with a host bind mount (`./docker/keys:/keys`)
# so operators can read generated keys directly from the host without
# docker cp.
WORKDIR /var/sshkey-chat

ENTRYPOINT ["sshkey-server"]
CMD ["-config", "/etc/sshkey-chat", "-data", "/var/sshkey-chat"]
