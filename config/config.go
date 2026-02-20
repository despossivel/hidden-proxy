package config

import (
	"os"
)

type Config struct {
	// endereço .onion da aplicação real (mantido em segredo)
	TargetOnion string
	// endereço .onion público do proxy (usado para reescrever redirects)
	ProxyOnion string
	// porta interna onde o proxy escuta
	ListenAddr string
	// endereço do SOCKS5 do Tor
	TorSOCKS string
}

func Load() *Config {
	return &Config{
		TargetOnion: getEnv("TARGET_ONION", ""),
		ProxyOnion:  getEnv("PROXY_ONION", ""),
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
