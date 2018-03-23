FROM openjdk:jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    openssl-dev \
    gcc \
    musl-dev \
    python-dev \
    swig

# ======
# OpenDJ
# ======
ENV OPENDJ_VERSION 3.0.0.gluu-SNAPSHOT
ENV OPENDJ_DOWNLOAD_URL http://ox.gluu.org/maven/org/forgerock/opendj/opendj-server-legacy/${OPENDJ_VERSION}/opendj-server-legacy-${OPENDJ_VERSION}.zip

RUN wget -q "$OPENDJ_DOWNLOAD_URL" -P /tmp \
    && mkdir -p /opt \
    && unzip -qq /tmp/opendj-server-legacy-${OPENDJ_VERSION}.zip -d /opt \
    && rm -f /tmp/opendj-server-legacy-${OPENDJ_VERSION}.zip

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

CMD ["sh", "/opt/scripts/entrypoint.sh"]
