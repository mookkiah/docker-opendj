FROM openjdk:jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    bash \
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
RUN pip install -U pip
RUN pip install "consulate==0.6.0" "m2crypto==0.22.3"

# ====
# misc
# ====
COPY schemas/96-eduperson.ldif /opt/opendj/template/config/schema/
COPY schemas/101-ox.ldif /opt/opendj/template/config/schema/
COPY schemas/77-customAttributes.ldif /opt/opendj/template/config/schema/
COPY templates /opt/templates
COPY scripts /opt/scripts

RUN chmod +x /opt/scripts/entrypoint.sh
CMD ["/opt/scripts/entrypoint.sh"]
