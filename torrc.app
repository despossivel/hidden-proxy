# Tor da aplicação — gera o .onion privado
SocksPort 9051
HiddenServiceDir /var/lib/tor/app_hidden_service/
HiddenServicePort 80 127.0.0.1:3000
