FROM docker.io/hashicorp/vault:2.1.0@sha256:5520cc26271c024e6ffa45cdf95255bd26b70d71ba4b7e0bc18925bef4128adb

USER root

COPY ci/scripts/init-vault.sh /usr/local/bin/init-vault.sh
RUN chmod +x /usr/local/bin/init-vault.sh

USER vault

ENTRYPOINT ["/usr/local/bin/init-vault.sh"]