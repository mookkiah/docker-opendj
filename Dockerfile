FROM openjdk:8-jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    openssl \
    shadow

# ======
# OpenDJ
# ======
ENV OPENDJ_VERSION 3.0.1.gluu
ENV OPENDJ_DOWNLOAD_URL http://ox.gluu.org/maven/org/forgerock/opendj/opendj-server-legacy/${OPENDJ_VERSION}/opendj-server-legacy-${OPENDJ_VERSION}.zip

RUN wget -q "$OPENDJ_DOWNLOAD_URL" -P /tmp \
    && mkdir -p /opt \
    && unzip -qq /tmp/opendj-server-legacy-${OPENDJ_VERSION}.zip -d /opt \
    && rm -f /tmp/opendj-server-legacy-${OPENDJ_VERSION}.zip

# ====
# Tini
# ====

ENV TINI_VERSION v0.18.0
RUN wget -q https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ======
# Python
# ======
COPY requirements.txt /tmp/requirements.txt
RUN pip install -U pip \
    && pip install -r /tmp/requirements.txt --no-cache-dir

# ====
# misc
# ====

EXPOSE 1636
EXPOSE 8989
EXPOSE 4444

# ==========
# Config ENV
# ==========
ENV GLUU_CONFIG_ADAPTER consul
ENV GLUU_CONFIG_CONSUL_HOST localhost
ENV GLUU_CONFIG_CONSUL_PORT 8500
# force to use default consistency mode
ENV GLUU_CONFIG_CONSUL_CONSISTENCY stale
ENV GLUU_CONFIG_CONSUL_SCHEME http
ENV GLUU_CONFIG_CONSUL_VERIFY false
ENV GLUU_CONFIG_CONSUL_CACERT_FILE /etc/certs/consul_ca.crt
ENV GLUU_CONFIG_CONSUL_CERT_FILE /etc/certs/consul_client.crt
ENV GLUU_CONFIG_CONSUL_KEY_FILE /etc/certs/consul_client.key
ENV GLUU_CONFIG_CONSUL_TOKEN_FILE /etc/certs/consul_token
ENV GLUU_CONFIG_KUBERNETES_NAMESPACE default
ENV GLUU_CONFIG_KUBERNETES_CONFIGMAP gluu

# ==========
# Secret ENV
# ==========
ENV GLUU_SECRET_ADAPTER vault
ENV GLUU_SECRET_VAULT_SCHEME http
ENV GLUU_SECRET_VAULT_HOST localhost
ENV GLUU_SECRET_VAULT_PORT 8200
ENV GLUU_SECRET_VAULT_VERIFY false
ENV GLUU_SECRET_VAULT_ROLE_ID_FILE /etc/certs/vault_role_id
ENV GLUU_SECRET_VAULT_SECRET_ID_FILE /etc/certs/vault_secret_id
ENV GLUU_SECRET_VAULT_CERT_FILE /etc/certs/vault_client.crt
ENV GLUU_SECRET_VAULT_KEY_FILE /etc/certs/vault_client.key
ENV GLUU_SECRET_VAULT_CACERT_FILE /etc/certs/vault_ca.crt
ENV GLUU_SECRET_KUBERNETES_NAMESPACE default
ENV GLUU_SECRET_KUBERNETES_SECRET gluu
ENV GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG false

# ===========
# Generic ENV
# ===========

ENV GLUU_CACHE_TYPE NATIVE_PERSISTENCE
ENV GLUU_REDIS_URL localhost:6379
ENV GLUU_REDIS_TYPE STANDALONE
ENV GLUU_MEMCACHED_URL localhost:11211
ENV GLUU_LDAP_INIT False
ENV GLUU_LDAP_INIT_HOST localhost
ENV GLUU_LDAP_INIT_PORT 1636
ENV GLUU_LDAP_ADDR_INTERFACE ""
ENV GLUU_LDAP_ADVERTISE_ADDR ""
ENV GLUU_OXTRUST_CONFIG_GENERATION false
ENV GLUU_LDAP_PORT 1389
ENV GLUU_LDAPS_PORT 1636
ENV GLUU_ADMIN_PORT 4444
ENV GLUU_REPLICATION_PORT 8989
ENV GLUU_JMX_PORT 1689

RUN mkdir -p /etc/certs /flag /deploy
COPY schemas/96-eduperson.ldif /opt/opendj/template/config/schema/
COPY schemas/101-ox.ldif /opt/opendj/template/config/schema/
COPY schemas/77-customAttributes.ldif /opt/opendj/template/config/schema/
COPY templates /opt/templates
COPY scripts /opt/scripts
RUN chmod +x /opt/scripts/entrypoint.sh

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
CMD ["/opt/scripts/entrypoint.sh"]
