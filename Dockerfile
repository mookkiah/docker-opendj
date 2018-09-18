FROM openjdk:8-jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    openssl

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
RUN mkdir -p /etc/certs
COPY schemas/96-eduperson.ldif /opt/opendj/template/config/schema/
COPY schemas/101-ox.ldif /opt/opendj/template/config/schema/
COPY schemas/77-customAttributes.ldif /opt/opendj/template/config/schema/
COPY templates /opt/templates
COPY scripts /opt/scripts
RUN chmod +x /opt/scripts/entrypoint.sh

ENV GLUU_CONFIG_ADAPTER consul
ENV GLUU_CONSUL_HOST localhost
ENV GLUU_CONSUL_PORT 8500
ENV GLUU_CONSUL_CONSISTENCY stale
ENV GLUU_CONSUL_SCHEME http
ENV GLUU_CONSUL_VERIFY false
ENV GLUU_CONSUL_CACERT_FILE /etc/certs/consul_ca.crt
ENV GLUU_CONSUL_CERT_FILE /etc/certs/consul_client.crt
ENV GLUU_CONSUL_KEY_FILE /etc/certs/consul_client.key
ENV GLUU_CONSUL_TOKEN_FILE /etc/certs/consul_token
ENV GLUU_KUBERNETES_NAMESPACE default
ENV GLUU_KUBERNETES_CONFIGMAP gluu
ENV GLUU_CACHE_TYPE IN_MEMORY
ENV GLUU_REDIS_URL localhost:6379
ENV GLUU_REDIS_TYPE STANDALONE
ENV GLUU_MEMCACHED_URL localhost:11211
ENV GLUU_LDAP_INIT False
ENV GLUU_LDAP_INIT_HOST localhost
ENV GLUU_LDAP_INIT_PORT 1636
ENV GLUU_LDAP_ADDR_INTERFACE ""
ENV GLUU_LDAP_ADVERTISE_ADDR ""
ENV GLUU_OXTRUST_CONFIG_GENERATION False
ENV GLUU_LDAP_PORT 1389
ENV GLUU_LDAPS_PORT 1636
ENV GLUU_ADMIN_PORT 4444
ENV GLUU_REPLICATION_PORT 8989
ENV GLUU_JMX_PORT 1689

EXPOSE 1636
EXPOSE 8989
EXPOSE 4444

ENTRYPOINT ["tini", "--"]
CMD ["/opt/scripts/wait-for-it", "/opt/scripts/entrypoint.sh"]
