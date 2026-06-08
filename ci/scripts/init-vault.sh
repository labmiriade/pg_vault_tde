#!/bin/sh
docker-entrypoint.sh server -dev -dev-root-token-id="${VAULT_MOCK_TOKEN}" &
VAULT_PID=$!

echo "[INIT] Awaiting vault..."
while ! wget -q --spider http://127.0.0.1:8200/v1/sys/health; do
    sleep 1
done

echo "[INIT] Vault up"
echo "[INIT] Configuration of Transit Engine..."

TOKEN=${VAULT_MOCK_TOKEN:-test-token}
MOUNT=${VAULT_MOCK_MOUNT:-transit}
KEY=${VAULT_MOCK_KEY_NAME:-pg-tde-dek}

wget -q -O - --header="X-Vault-Token: ${TOKEN}" \
    --post-data='{"type":"transit"}' \
    http://127.0.0.1:8200/v1/sys/mounts/${MOUNT} > /dev/null

wget -q -O - --header="X-Vault-Token: ${TOKEN}" \
    --post-data='' \
    http://127.0.0.1:8200/v1/${MOUNT}/keys/${KEY} > /dev/null

echo "[INIT] Vault configuration completed"

wait $VAULT_PID