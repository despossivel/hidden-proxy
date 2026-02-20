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
	log.Printf("proxy público: %s", cfg.ProxyOnion)
	log.Printf("destino: [REDACTED] (configurado via TARGET_ONION)")
	log.Printf("tor SOCKS5: %s", cfg.TorSOCKS)

	p, err := proxy.New(cfg.TargetOnion, cfg.ProxyOnion, cfg.TorSOCKS)
	if err != nil {
		log.Fatalf("erro ao iniciar proxy: %v", err)
	}

	if err := http.ListenAndServe(cfg.ListenAddr, p); err != nil {
		log.Fatalf("erro no servidor: %v", err)
	}
}
