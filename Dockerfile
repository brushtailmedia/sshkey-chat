# Build stage
FROM golang:1.25-alpine AS builder

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

ENTRYPOINT ["sshkey-server"]
CMD ["-config", "/etc/sshkey-chat", "-data", "/var/sshkey-chat"]
