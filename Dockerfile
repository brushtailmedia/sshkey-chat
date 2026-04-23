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
    && addgroup -S sshkey \
    && adduser -S -G sshkey -h /var/sshkey-chat sshkey

COPY --from=builder /sshkey-server /usr/local/bin/sshkey-server
COPY --from=builder /sshkey-ctl /usr/local/bin/sshkey-ctl

# Config and data directories
RUN mkdir -p /etc/sshkey-chat /var/sshkey-chat/data \
    && chown -R sshkey:sshkey /etc/sshkey-chat /var/sshkey-chat

VOLUME ["/etc/sshkey-chat", "/var/sshkey-chat"]

EXPOSE 2222

USER sshkey

# WORKDIR matters for `docker exec sshkey-ctl bootstrap-admin` — the
# command writes the generated admin private key to CWD. With no
# WORKDIR, `docker exec` runs in `/` which sshkey cannot write to, so
# bootstrap-admin fails with a permission error. /var/sshkey-chat is
# the sshkey user's home dir AND is mounted as a persistent volume in
# docker-compose.yml, so the generated key survives container restarts
# until the operator extracts it with `docker cp`.
WORKDIR /var/sshkey-chat

ENTRYPOINT ["sshkey-server"]
CMD ["-config", "/etc/sshkey-chat", "-data", "/var/sshkey-chat"]
