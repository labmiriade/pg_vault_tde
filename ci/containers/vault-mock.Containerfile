# ci/containers/vault-mock.Containerfile
#
# Lightweight mock Vault server for pg_vault_tde integration tests.
# Implements the Transit API /datakey/plaintext endpoint.
#
# Build:  podman build -f ci/containers/vault-mock.Containerfile -t vault-mock ci/vault-mock/
# Run:    podman run --rm -p 8200:8200 -e VAULT_MOCK_TOKEN=test-token vault-mock

FROM docker.io/library/golang:1.21-bookworm AS builder

WORKDIR /src
COPY ci/vault-mock/go.mod ci/vault-mock/vault_mock.go ./
RUN go build -ldflags="-s -w" -o /vault-mock .

FROM docker.io/library/debian:bookworm-slim

# Non-root user for security
RUN groupadd -r vault && useradd -r -g vault vault
COPY --from=builder /vault-mock /usr/local/bin/vault-mock
RUN chmod 755 /usr/local/bin/vault-mock

USER vault

ENV VAULT_MOCK_PORT=8200
ENV VAULT_MOCK_TOKEN=test-token
ENV VAULT_MOCK_MOUNT=transit
ENV VAULT_MOCK_KEY_NAME=pg-tde-dek

EXPOSE 8200

HEALTHCHECK --interval=5s --timeout=2s --retries=3 \
    CMD ["/usr/local/bin/vault-mock", "--health-check"] || exit 1

ENTRYPOINT ["/usr/local/bin/vault-mock"]
