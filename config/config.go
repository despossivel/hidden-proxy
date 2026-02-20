package config

import (
	"os"
)

type Config struct {
	// .onion address of the real app (kept secret)
	TargetOnion string
	// public .onion address of the proxy (used to rewrite redirects)
	ProxyOnion string
	// internal port where the proxy listens
	ListenAddr string
	// Tor SOCKS5 address
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
