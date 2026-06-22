# ci/openbao/bao-1.hcl — OpenBao node 1 (Raft) production config
# Integrated Storage (Raft) HA cluster. retry_join lists all peers so any
# node can locate the leader regardless of boot order.

storage "raft" {
  path    = "/openbao/file"
  node_id = "bao-1"
  retry_join { leader_api_addr = "http://bao-1:8200" }
  retry_join { leader_api_addr = "http://bao-2:8200" }
  retry_join { leader_api_addr = "http://bao-3:8200" }
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = true
}

api_addr      = "http://bao-1:8200"
cluster_addr  = "http://bao-1:8201"
disable_mlock = true
ui            = false
