#!/bin/sh
set -e

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

python3 /app/scripts/ldap_replicator.py &

# run OpenDJ server
exec /opt/opendj/bin/start-ds -N
