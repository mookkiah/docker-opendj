#!/bin/sh
set -e

# =========
# FUNCTIONS
# =========

set_java_args() {
    # not sure if we can omit `-server` safely
    local java_args="-server"
    java_args="${java_args} -XX:+UseContainerSupport -XX:MaxRAMPercentage=${GLUU_MAX_RAM_PERCENTAGE} ${GLUU_JAVA_OPTIONS}"
    # set the env var so it is loaded by `start-ds` script
    export OPENDJ_JAVA_ARGS=${java_args}
}

# ==========
# ENTRYPOINT
# ==========

mkdir -p /opt/opendj/locks

export JAVA_VERSION=$(java -version 2>&1 | awk -F '[\"_]' 'NR==1{print $2}')

python3 /app/scripts/wait.py

if [ ! -f /deploy/touched ]; then
    python3 /app/scripts/entrypoint.py
    touch /deploy/touched
fi

serf agent -config-file /etc/gluu/conf/serf.json &

python3 /app/scripts/ldap_peer.py
python3 /app/scripts/ldap_replicator.py &

# run OpenDJ server
set_java_args
exec /opt/opendj/bin/start-ds -N
