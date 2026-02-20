# Task: Tor Onion-to-Onion Reverse Proxy em Go

## Objetivo

Construir um proxy reverso em Go que:
- Expõe um endereço `.onion` público (o que o usuário acessa)
- Encaminha todo o tráfego para outro endereço `.onion` privado (a aplicação real)
- Serve de forma transparente HTML, CSS, JS, imagens e qualquer outro conteúdo
- Nunca expõe o endereço `.onion` real da aplicação

---

## Diagrama de Fluxo

```
┌─────────────┐        Rede Tor         ┌─────────────────────┐        Rede Tor         ┌──────────────────┐
│             │                         │                     │                         │                  │
│   USUÁRIO   │ ──── requisição ──────► │   PROXY (.onion A)  │ ──── repassa ─────────► │  APP (.onion B)  │
│             │                         │                     │                         │                  │
│             │ ◄─── resposta ───────── │   proxy reverso Go  │ ◄─── resposta ───────── │  (nunca exposta) │
│             │    (html/css/img/etc)   │                     │    (html/css/img/etc)   │                  │
└─────────────┘                         └─────────────────────┘                         └──────────────────┘

Usuário conhece: .onion A  ✅
Usuário conhece: .onion B  ❌ (nunca exposto)
Proxy conhece:   .onion B  ✅ (configurado via env/config)
```

---

## Arquitetura

### Componentes

```
tor-onion-proxy/
├── main.go                  # entrypoint
├── proxy/
│   └── proxy.go             # lógica do proxy reverso
├── tor/
│   └── client.go            # cliente HTTP via SOCKS5 do Tor
├── config/
│   └── config.go            # configuração via env
├── docker-compose.yml       # orquestração
├── Dockerfile               # build do proxy
├── torrc.proxy              # configuração do Tor para o proxy
└── torrc.app                # configuração do Tor para a aplicação (referência)
```

### Fluxo interno

```
Requisição chega no :8080 (porta interna do proxy)
        ↓
Tor expõe essa porta como .onion A
        ↓
proxy.go recebe a requisição
        ↓
tor/client.go cria conexão via SOCKS5 (127.0.0.1:9050)
        ↓
Requisição é repassada para .onion B via rede Tor
        ↓
Resposta volta pelo mesmo caminho
        ↓
proxy.go devolve resposta ao usuário
```

---

## Código

### config/config.go

```go
package config

import (
	"os"
)

type Config struct {
	// endereço .onion da aplicação real (mantido em segredo)
	TargetOnion string
	// porta interna onde o proxy escuta
	ListenAddr string
	// endereço do SOCKS5 do Tor
	TorSOCKS string
}

func Load() *Config {
	return &Config{
		TargetOnion: getEnv("TARGET_ONION", ""),
		ListenAddr:  getEnv("LISTEN_ADDR", ":8080"),
		TorSOCKS:    getEnv("TOR_SOCKS", "127.0.0.1:9050"),
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
```

---

### tor/client.go

```go
package tor

import (
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// NewHTTPClient cria um cliente HTTP que roteia todo tráfego
// pelo SOCKS5 do Tor — permitindo resolver endereços .onion
func NewHTTPClient(socksAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		// não seguir redirects automaticamente — deixar o cliente decidir
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
```

---

### proxy/proxy.go

```go
package proxy

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	torClient "tor-onion-proxy/tor"
)

type ReverseProxy struct {
	targetOnion string
	client      *http.Client
}

func New(targetOnion, socksAddr string) (*ReverseProxy, error) {
	client, err := torClient.NewHTTPClient(socksAddr)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar cliente tor: %w", err)
	}

	return &ReverseProxy{
		targetOnion: strings.TrimRight(targetOnion, "/"),
		client:      client,
	}, nil
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// monta a URL de destino — substitui o host pelo .onion real da app
	targetURL := fmt.Sprintf("http://%s%s", p.targetOnion, r.RequestURI)

	// cria a requisição para a aplicação
	outReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "erro ao criar requisição", http.StatusInternalServerError)
		return
	}

	// copia os headers originais
	copyHeaders(outReq.Header, r.Header)

	// remove headers que poderiam expor informações do proxy
	outReq.Header.Del("X-Forwarded-For")
	outReq.Header.Del("X-Real-IP")
	outReq.Header.Set("Host", p.targetOnion)

	// faz a requisição para a aplicação via Tor
	resp, err := p.client.Do(outReq)
	if err != nil {
		log.Printf("erro ao contatar aplicação: %v", err)
		http.Error(w, "aplicação indisponível", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// copia headers da resposta para o cliente
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// transmite o body — funciona para HTML, CSS, JS, imagens, etc
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("erro ao transmitir resposta: %v", err)
	}

	log.Printf("%s %s → %d (%d bytes) em %v",
		r.Method, r.RequestURI, resp.StatusCode, written, time.Since(start))
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
```

---

### main.go

```go
package main

import (
	"log"
	"net/http"

	"tor-onion-proxy/config"
	"tor-onion-proxy/proxy"
)

func main() {
	cfg := config.Load()

	if cfg.TargetOnion == "" {
		log.Fatal("TARGET_ONION não definido — configure o endereço .onion da aplicação")
	}

	log.Printf("iniciando proxy")
	log.Printf("escutando em: %s", cfg.ListenAddr)
	log.Printf("destino: [REDACTED] (configurado via TARGET_ONION)")
	log.Printf("tor SOCKS5: %s", cfg.TorSOCKS)

	p, err := proxy.New(cfg.TargetOnion, cfg.TorSOCKS)
	if err != nil {
		log.Fatalf("erro ao iniciar proxy: %v", err)
	}

	if err := http.ListenAndServe(cfg.ListenAddr, p); err != nil {
		log.Fatalf("erro no servidor: %v", err)
	}
}
```

---

### go.mod

```
module tor-onion-proxy

go 1.21

require golang.org/x/net v0.20.0
```

---

## Configuração do Tor

### torrc.proxy
```
# Tor do proxy — gera o .onion público que o usuário acessa
SocksPort 9050
HiddenServiceDir /var/lib/tor/proxy_hidden_service/
HiddenServicePort 80 127.0.0.1:8080
```

O arquivo `/var/lib/tor/proxy_hidden_service/hostname` conterá o endereço `.onion A` gerado automaticamente.

### torrc.app (referência — configuração da aplicação real)
```
# Tor da aplicação — gera o .onion privado
SocksPort 9051
HiddenServiceDir /var/lib/tor/app_hidden_service/
HiddenServicePort 80 127.0.0.1:3000
```

O endereço gerado aqui é o `TARGET_ONION` que você passa para o proxy via variável de ambiente.

---

## Docker

### Dockerfile
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o proxy .

FROM alpine:latest
RUN apk add --no-cache tor ca-certificates

WORKDIR /app
COPY --from=builder /app/proxy .
COPY torrc.proxy /etc/tor/torrc

# script de inicialização — sobe o Tor e depois o proxy
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
```

### entrypoint.sh
```bash
#!/bin/sh
set -e

echo "iniciando Tor..."
tor -f /etc/tor/torrc &
TOR_PID=$!

# aguarda o Tor inicializar e gerar o endereço .onion
echo "aguardando Tor..."
sleep 10

ONION_ADDR=$(cat /var/lib/tor/proxy_hidden_service/hostname)
echo "endereço público do proxy: $ONION_ADDR"

echo "iniciando proxy..."
./proxy

# cleanup
kill $TOR_PID
```

### docker-compose.yml
```yaml
version: '3.8'

services:
  proxy:
    build: .
    environment:
      # endereço .onion da aplicação real — nunca exposto ao usuário
      - TARGET_ONION=${TARGET_ONION}
      - LISTEN_ADDR=:8080
      - TOR_SOCKS=127.0.0.1:9050
    volumes:
      # persiste o endereço .onion do proxy entre restarts
      - tor_proxy_data:/var/lib/tor/proxy_hidden_service
    restart: unless-stopped

volumes:
  tor_proxy_data:
```

---

## Como usar

### 1. Configurar a aplicação real

Na máquina da aplicação, configure o Tor com `torrc.app` e anote o endereço `.onion` gerado em `/var/lib/tor/app_hidden_service/hostname`.

### 2. Subir o proxy

```bash
# define o endereço .onion da aplicação (mantido em segredo)
export TARGET_ONION="seuenderecosecreto.onion"

docker compose up -d
```

### 3. Obter o endereço público do proxy

```bash
docker compose exec proxy cat /var/lib/tor/proxy_hidden_service/hostname
# ex: abcdef1234567890.onion  ← esse é o que você divulga
```

### 4. Acessar

O usuário acessa `abcdef1234567890.onion` via Tor Browser. Todo o tráfego flui de forma transparente para a aplicação real sem que o endereço dela seja exposto.

---

## Considerações de segurança

**O proxy conhece o TARGET_ONION** — proteja a variável de ambiente e os logs. Nunca logue o valor do `TARGET_ONION`.

**Persistência do .onion do proxy** — o volume `tor_proxy_data` garante que o endereço público não mude entre restarts. Faça backup da chave privada em `/var/lib/tor/proxy_hidden_service/`.

**Logs** — o proxy loga métodos e paths mas nunca o endereço de destino. Considere desativar logs em produção ou usar um log rotativo com retenção curta.

**Latência** — o tráfego percorre a rede Tor duas vezes (usuário→proxy e proxy→app). Isso é esperado e é o custo da privacidade.
