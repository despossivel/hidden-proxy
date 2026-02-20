# Application Tor — generates the private .onion
SocksPort 9051
HiddenServiceDir /var/lib/tor/app_hidden_service/
HiddenServicePort 80 127.0.0.1:3000
