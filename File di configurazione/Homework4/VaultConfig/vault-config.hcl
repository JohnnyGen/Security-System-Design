# Listener TCP per HTTPS
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "C:/Users/gioge/Desktop/System Security/HW4/Config/localhost.crt"  # Il percorso al certificato
  tls_key_file  =  "C:/Users/gioge/Desktop/System Security/HW4/Config/private_key.key"  # Il percorso alla chiave privata
  api_addr = "https://127.0.0.1:8200"
}

# Backend di storage in modalità sviluppo
storage "file" {
  path = "C:/Program Files/Vault/data"
}

# Abilitare la UI
ui = true

# Configurazioni aggiuntive
disable_mlock = true