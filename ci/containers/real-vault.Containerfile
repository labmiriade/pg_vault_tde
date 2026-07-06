FROM docker.io/hashicorp/vault:latest

USER root

COPY ci/scripts/init-vault.sh /usr/local/bin/init-vault.sh
RUN chmod +x /usr/local/bin/init-vault.sh

USER vault

ENTRYPOINT ["/usr/local/bin/init-vault.sh"]