# Task: Camada de Resiliência — Múltiplos Proxies com Descoberta via IPFS/IPNS

## Objetivo

Estender o proxy Tor existente para suportar múltiplas instâncias paralelas,
onde cada instância gera seu próprio endereço `.onion` e publica sua disponibilidade
numa lista mantida no IPFS via IPNS — permitindo que usuários descubram automaticamente
quais proxies estão online.

---

## Diagrama de Fluxo

```
                        IPFS/IPNS
                   ┌─────────────────┐
                   │  proxy-list.json│  ← lista de .onions ativos
                   │  (CID via IPNS) │
                   └────────┬────────┘
                            │ usuário consulta
                            ▼
┌─────────────────────────────────────────────────┐
│                   USUÁRIO                        │
│  1. busca lista no IPNS                         │
│  2. tenta proxies da lista até achar um ativo   │
└──────┬──────────────────────────┬───────────────┘
       │                          │
       ▼                          ▼
┌─────────────┐            ┌─────────────┐
│  Proxy A    │            │  Proxy B    │       ...Proxy N
│ .onion AAA  │            │ .onion BBB  │
│  (ativo)    │            │  (caiu)     │
└──────┬──────┘            └─────────────┘
       │
       ▼
┌─────────────┐
│     APP     │
│ .onion ZZZ  │
│  (privado)  │
└─────────────┘
```

---

## Arquitetura

```
tor-proxy-resiliencia/
├── publisher/
│   ├── main.go          # publica/atualiza lista de proxies no IPFS
│   └── ipfs.go          # client IPFS + IPNS
├── healthcheck/
│   └── checker.go       # verifica quais proxies estão ativos
├── scripts/
│   ├── deploy-proxy.sh  # sobe nova instância de proxy
│   └── update-list.sh   # atualiza lista no IPNS
├── docker-compose.yml   # múltiplas instâncias do proxy
└── proxy-list.schema.json
```

---

## Schema da lista de proxies

### proxy-list.schema.json
```json
{
  "updated_at": "2024-01-01T00:00:00Z",
  "proxies": [
    {
      "onion": "abcdef1234567890.onion",
      "added_at": "2024-01-01T00:00:00Z",
      "active": true
    },
    {
      "onion": "fedcba0987654321.onion",
      "added_at": "2024-01-01T00:00:00Z",
      "active": false
    }
  ]
}
```

---

## Código

### healthcheck/checker.go

```go
package healthcheck

import (
	"context"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

type Result struct {
	Onion  string
	Active bool
}

// Check verifica se um endereço .onion está respondendo via Tor
func Check(onion, socksAddr string) Result {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return Result{Onion: onion, Active: false}
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", "http://"+onion, nil)
	if err != nil {
		return Result{Onion: onion, Active: false}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("proxy %s inativo: %v", onion, err)
		return Result{Onion: onion, Active: false}
	}
	defer resp.Body.Close()

	active := resp.StatusCode < 500
	log.Printf("proxy %s → status %d → ativo: %v", onion, resp.StatusCode, active)
	return Result{Onion: onion, Active: active}
}

// CheckAll verifica todos os proxies da lista em paralelo
func CheckAll(onions []string, socksAddr string) []Result {
	results := make([]Result, len(onions))
	ch := make(chan struct {
		idx    int
		result Result
	}, len(onions))

	for i, onion := range onions {
		go func(idx int, o string) {
			ch <- struct {
				idx    int
				result Result
			}{idx, Check(o, socksAddr)}
		}(i, onion)
	}

	for range onions {
		r := <-ch
		results[r.idx] = r.result
	}

	return results
}
```

---

### publisher/ipfs.go

```go
package publisher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type IPFSClient struct {
	apiURL string
	client *http.Client
}

type ProxyEntry struct {
	Onion   string    `json:"onion"`
	AddedAt time.Time `json:"added_at"`
	Active  bool      `json:"active"`
}

type ProxyList struct {
	UpdatedAt time.Time    `json:"updated_at"`
	Proxies   []ProxyEntry `json:"proxies"`
}

func NewIPFSClient(apiURL string) *IPFSClient {
	return &IPFSClient{
		apiURL: apiURL,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Add publica o JSON no IPFS e retorna o CID
func (c *IPFSClient) Add(list ProxyList) (string, error) {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return "", err
	}

	resp, err := c.client.Post(
		c.apiURL+"/api/v0/add",
		"application/octet-stream",
		bytes.NewReader(data),
	)
	if err != nil {
		return "", fmt.Errorf("erro ao publicar no IPFS: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Hash string `json:"Hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Hash, nil
}

// PublishIPNS aponta a chave IPNS para o novo CID
func (c *IPFSClient) PublishIPNS(cid, keyName string) (string, error) {
	url := fmt.Sprintf("%s/api/v0/name/publish?arg=%s&key=%s", c.apiURL, cid, keyName)

	resp, err := c.client.Post(url, "", nil)
	if err != nil {
		return "", fmt.Errorf("erro ao publicar IPNS: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Name  string `json:"Name"`
		Value string `json:"Value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return result.Name, nil
}
```

---

### publisher/main.go

```go
package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"tor-proxy-resiliencia/healthcheck"
	"tor-proxy-resiliencia/publisher"
)

func main() {
	ipfsAPI  := getEnv("IPFS_API", "http://127.0.0.1:5001")
	ipnsKey  := getEnv("IPNS_KEY", "proxy-list")
	torSOCKS := getEnv("TOR_SOCKS", "127.0.0.1:9050")
	interval := 5 * time.Minute

	onions := loadKnownProxies()
	if len(onions) == 0 {
		log.Fatal("nenhum proxy configurado — defina KNOWN_PROXIES")
	}

	ipfs := publisher.NewIPFSClient(ipfsAPI)

	log.Printf("iniciando publisher — verificando %d proxies a cada %v", len(onions), interval)

	for {
		log.Println("verificando proxies...")
		results := healthcheck.CheckAll(onions, torSOCKS)

		list := publisher.ProxyList{
			UpdatedAt: time.Now().UTC(),
			Proxies:   make([]publisher.ProxyEntry, len(results)),
		}

		for i, r := range results {
			list.Proxies[i] = publisher.ProxyEntry{
				Onion:   r.Onion,
				AddedAt: time.Now().UTC(),
				Active:  r.Active,
			}
		}

		cid, err := ipfs.Add(list)
		if err != nil {
			log.Printf("erro ao publicar no IPFS: %v", err)
		} else {
			log.Printf("lista publicada → CID: %s", cid)

			ipnsAddr, err := ipfs.PublishIPNS(cid, ipnsKey)
			if err != nil {
				log.Printf("erro ao atualizar IPNS: %v", err)
			} else {
				log.Printf("IPNS atualizado → /ipns/%s", ipnsAddr)
			}
		}

		time.Sleep(interval)
	}
}

func loadKnownProxies() []string {
	if raw := os.Getenv("KNOWN_PROXIES"); raw != "" {
		return strings.Split(raw, ",")
	}

	if file := os.Getenv("PROXY_LIST_FILE"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("erro ao ler arquivo de proxies: %v", err)
		}
		var list []string
		if err := json.Unmarshal(data, &list); err != nil {
			log.Fatalf("erro ao parsear arquivo de proxies: %v", err)
		}
		return list
	}

	return nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
```

---

## Docker

### docker-compose.yml

```yaml
version: '3.8'

services:

  proxy:
    image: tor-onion-proxy:latest  # imagem da task anterior
    environment:
      - TARGET_ONION=${TARGET_ONION}
      - LISTEN_ADDR=:8080
      - TOR_SOCKS=127.0.0.1:9050
    volumes:
      - tor_proxy_data:/var/lib/tor/proxy_hidden_service
    restart: unless-stopped

  ipfs:
    image: ipfs/kubo:latest
    ports:
      - "5001:5001"
      - "8080:8080"
    volumes:
      - ipfs_data:/data/ipfs
    restart: unless-stopped

  publisher:
    build:
      context: .
      dockerfile: Dockerfile.publisher
    environment:
      - IPFS_API=http://ipfs:5001
      - IPNS_KEY=proxy-list
      - TOR_SOCKS=127.0.0.1:9050
      - KNOWN_PROXIES=${KNOWN_PROXIES}
    depends_on:
      - ipfs
    restart: unless-stopped

volumes:
  tor_proxy_data:
  ipfs_data:
```

### Dockerfile.publisher

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o publisher ./publisher

FROM alpine:latest
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/publisher .

CMD ["./publisher"]
```

---

## Scripts

### scripts/deploy-proxy.sh

```bash
#!/bin/bash
set -e

TARGET_ONION=$1
if [ -z "$TARGET_ONION" ]; then
  echo "uso: ./deploy-proxy.sh <target-onion>"
  exit 1
fi

CURRENT=$(docker compose ps proxy -q | wc -l)
NEXT=$(( CURRENT + 1 ))

echo "subindo instância $NEXT do proxy..."
TARGET_ONION=$TARGET_ONION docker compose up -d --scale proxy=$NEXT

sleep 15

ONIONS=$(docker compose ps proxy -q | xargs -I{} docker exec {} cat /var/lib/tor/proxy_hidden_service/hostname 2>/dev/null | tr '\n' ',' | sed 's/,$//')

echo ""
echo "proxies ativos: $ONIONS"
echo ""
echo "adicione ao .env:"
echo "KNOWN_PROXIES=$ONIONS"
```

### scripts/update-list.sh

```bash
#!/bin/bash
docker compose restart publisher
echo "publisher reiniciado — lista será atualizada em instantes"
docker compose logs -f publisher
```

---

## Como usar

### 1. Subir o ambiente

```bash
export TARGET_ONION="appsecreto.onion"
export KNOWN_PROXIES=""

docker compose up -d
```

### 2. Escalar proxies e coletar endereços

```bash
./scripts/deploy-proxy.sh $TARGET_ONION
# anote os endereços .onion gerados
```

### 3. Atualizar o publisher

```bash
# .env
KNOWN_PROXIES=aaa111.onion,bbb222.onion,ccc333.onion

./scripts/update-list.sh
```

### 4. Obter o endereço IPNS para divulgar

```bash
docker compose logs publisher | grep "IPNS atualizado"
# ex: IPNS atualizado → /ipns/k51qzi5uqu5...
```

Esse endereço IPNS é fixo e é o único que você precisa divulgar. A lista por trás dele é atualizada automaticamente a cada 5 minutos.

---

## Considerações

**IPNS tem latência de propagação** — pode levar alguns minutos para a lista atualizada ser visível globalmente. Para mitigar, use um pinning service como Pinata para garantir disponibilidade imediata.

**O publisher conhece todos os endereços** — em cenários de alta segurança, cada operador de proxy poderia publicar sua própria disponibilidade de forma independente em vez de ter um publisher centralizado.

**Backup da chave IPNS** — sem ela você perde o endereço fixo:

```bash
docker compose exec ipfs ipfs key export proxy-list > proxy-list.key
```
