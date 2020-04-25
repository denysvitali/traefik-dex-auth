FROM golang:latest AS builder
ENV PRJ=/go/src/github.com/denysvitali/traefik-dex-auth
RUN mkdir -p $PRJ
WORKDIR $PRJ
COPY . $PRJ
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/traefik-dex-auth main.go
RUN chmod u+x /tmp/traefik-dex-auth

FROM alpine:latest
ENV GIN_MODE=release
COPY --from=builder /tmp/traefik-dex-auth /bin/traefik-dex-auth
ENTRYPOINT ["traefik-dex-auth"]
