# ci/openbao/bao-3.hcl — OpenBao node 3 (Raft) production config

storage "raft" {
  path    = "/openbao/file"
  node_id = "bao-3"
  retry_join { leader_api_addr = "http://bao-1:8200" }
  retry_join { leader_api_addr = "http://bao-2:8200" }
  retry_join { leader_api_addr = "http://bao-3:8200" }
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = true
}

api_addr      = "http://bao-3:8200"
cluster_addr  = "http://bao-3:8201"
disable_mlock = true
ui            = false
