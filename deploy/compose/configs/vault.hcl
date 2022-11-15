
plugin_directory="/vault/plugins"
disable_mlock = "true"
ui = "true"

cluster_addr = "https://$(NAME):8201"
api_addr = "https://$(NAME):8200"

listener "tcp" {
    address = "[::]:8200"
    cluster_address = "[::]:8201"

    tls_cert_file = "/vault/config/tls/$(NAME).crt"
    tls_key_file = "/vault/config/tls/$(NAME).pem"
}

storage "raft" {
    path = "/vault/file"
    node_id = "$(NAME)"
}
