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
		log.Fatal("TARGET_ONION not set — configure the app's .onion address")
	}

	log.Printf("starting proxy")
	log.Printf("listening on: %s", cfg.ListenAddr)
	log.Printf("public proxy: %s", cfg.ProxyOnion)
	log.Printf("target: [REDACTED] (set via TARGET_ONION)")
	log.Printf("tor SOCKS5: %s", cfg.TorSOCKS)

	p, err := proxy.New(cfg.TargetOnion, cfg.ProxyOnion, cfg.TorSOCKS)
	if err != nil {
		log.Fatalf("failed to start proxy: %v", err)
	}

	if err := http.ListenAndServe(cfg.ListenAddr, p); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
