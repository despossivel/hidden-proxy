FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /tmp/proxy-bin .

FROM alpine:latest
RUN apk add --no-cache tor ca-certificates

WORKDIR /app
COPY --from=builder /tmp/proxy-bin ./proxy
COPY torrc.proxy /etc/tor/torrc

# script de inicialização — sobe o Tor e depois o proxy
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
