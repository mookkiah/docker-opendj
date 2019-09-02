FROM openjdk:8-jre-alpine3.9

# ===============
# Alpine packages
# ===============

RUN apk update && apk add --no-cache \
    py-pip \
    openssl \
    shadow \
    git

# ======
# OpenDJ
# ======

ENV OPENDJ_VERSION=3.0.1.gluu \
    OPENDJ_BUILD_DATE=2018-08-01

RUN wget -q https://ox.gluu.org/maven/org/forgerock/opendj/opendj-server-legacy/${OPENDJ_VERSION}/opendj-server-legacy-${OPENDJ_VERSION}.zip -P /tmp \
    && mkdir -p /opt \
    && unzip -qq /tmp/opendj-server-legacy-${OPENDJ_VERSION}.zip -d /opt \
    && rm -f /tmp/opendj-server-legacy-${OPENDJ_VERSION}.zip

# ====
# Tini
# ====

RUN wget -q https://github.com/krallin/tini/releases/download/v0.18.0/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ======
# Python
# ======

COPY requirements.txt /tmp/requirements.txt
RUN pip install -U pip \
    && pip install -r /tmp/requirements.txt --no-cache-dir \
    && apk del git

# =======
# License
# =======

RUN mkdir -p /licenses
COPY LICENSE /licenses/

# ====
# misc
# ====

EXPOSE 1636
EXPOSE 8989
EXPOSE 4444

# ==========
# Config ENV
# ==========

ENV GLUU_CONFIG_ADAPTER=consul \
    GLUU_CONFIG_CONSUL_HOST=localhost \
    GLUU_CONFIG_CONSUL_PORT=8500 \
    GLUU_CONFIG_CONSUL_CONSISTENCY=stale \
    GLUU_CONFIG_CONSUL_SCHEME=http \
    GLUU_CONFIG_CONSUL_VERIFY=false \
    GLUU_CONFIG_CONSUL_CACERT_FILE=/etc/certs/consul_ca.crt \
    GLUU_CONFIG_CONSUL_CERT_FILE=/etc/certs/consul_client.crt \
    GLUU_CONFIG_CONSUL_KEY_FILE=/etc/certs/consul_client.key \
    GLUU_CONFIG_CONSUL_TOKEN_FILE=/etc/certs/consul_token \
    GLUU_CONFIG_KUBERNETES_NAMESPACE=default \
    GLUU_CONFIG_KUBERNETES_CONFIGMAP=gluu \
    GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG=false

# ==========
# Secret ENV
# ==========

ENV GLUU_SECRET_ADAPTER=vault \
    GLUU_SECRET_VAULT_SCHEME=http \
    GLUU_SECRET_VAULT_HOST=localhost \
    GLUU_SECRET_VAULT_PORT=8200 \
    GLUU_SECRET_VAULT_VERIFY=false \
    GLUU_SECRET_VAULT_ROLE_ID_FILE=/etc/certs/vault_role_id \
    GLUU_SECRET_VAULT_SECRET_ID_FILE=/etc/certs/vault_secret_id \
    GLUU_SECRET_VAULT_CERT_FILE=/etc/certs/vault_client.crt \
    GLUU_SECRET_VAULT_KEY_FILE=/etc/certs/vault_client.key \
    GLUU_SECRET_VAULT_CACERT_FILE=/etc/certs/vault_ca.crt \
    GLUU_SECRET_KUBERNETES_NAMESPACE=default \
    GLUU_SECRET_KUBERNETES_SECRET=gluu \
    GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG=false

# ===============
# Persistence ENV
# ===============

ENV GLUU_PERSISTENCE_TYPE=ldap \
    GLUU_PERSISTENCE_LDAP_MAPPING=default

# ===========
# Generic ENV
# ===========

ENV GLUU_CACHE_TYPE=IN_MEMORY \
    GLUU_LDAP_ADDR_INTERFACE="" \
    GLUU_LDAP_ADVERTISE_ADDR="" \
    GLUU_OXTRUST_CONFIG_GENERATION=true \
    GLUU_ADMIN_PORT=4444 \
    GLUU_REPLICATION_PORT=8989 \
    GLUU_JMX_PORT=1689 \
    GLUU_WAIT_MAX_TIME=300 \
    GLUU_WAIT_SLEEP_DURATION=5

# ====
# misc
# =====

LABEL name="OpenDJ" \
    maintainer="Gluu Inc. <support@gluu.org>" \
    vendor="Gluu Federation" \
    version="4.0.0" \
    release="dev" \
    summary="Gluu OpenDJ" \
    description="Community fork of OpenDJ, an LDAP server originally developed by ForgeRock"

RUN mkdir -p /etc/certs /flag /deploy /app/tmp
COPY schemas/96-eduperson.ldif /opt/opendj/template/config/schema/
COPY schemas/101-ox.ldif /opt/opendj/template/config/schema/
COPY schemas/77-customAttributes.ldif /opt/opendj/template/config/schema/
COPY templates /app/templates
COPY scripts /app/scripts
RUN chmod +x /app/scripts/entrypoint.sh

# # create ldap user
# RUN useradd -ms /bin/sh --uid 1000 ldap \
#     && usermod -a -G root ldap

# # adjust ownership
# RUN chown -R 1000:1000 /opt/opendj \
#     && chown -R 1000:1000 /flag \
#     && chown -R 1000:1000 /deploy \
#     && chgrp -R 0 /opt/opendj && chmod -R g=u /opt/opendj \
#     && chgrp -R 0 /flag && chmod -R g=u /flag \
#     && chgrp -R 0 /deploy && chmod -R g=u /deploy \
#     && chgrp -R 0 /etc/certs && chmod -R g=u /etc/certs \
#     && chgrp -R 0 /etc/ssl && chmod -R g=u /etc/ssl

# # run as non-root user
# USER 1000

ENTRYPOINT ["tini", "-g", "--"]
CMD ["/app/scripts/entrypoint.sh"]
