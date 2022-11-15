plugin_directory="/vault/plugins"
disable_mlock = "true"
ui = "true"

cluster_addr = "https://vault-4:8201"
api_addr = "https://vault-4:8200"

listener "tcp" {
    address = "[::]:8200"
    cluster_address = "[::]:8201"

    tls_cert_file = "/vault/config/tls/vault-4.crt"
    tls_key_file = "/vault/config/tls/vault-4.pem"
}

storage "raft" {
    path = "/vault/file"
    node_id = "vault-4"
}
