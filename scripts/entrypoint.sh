#!/bin/sh
set -e

# =========
# FUNCTIONS
# =========

run_wait() {
    python /app/scripts/wait.py
}

run_entrypoint() {
    if [ ! -f /deploy/touched ]; then
        python /app/scripts/entrypoint.py
        touch /deploy/touched
    fi
}

run_ldap_peer() {
    python /app/scripts/ldap_peer.py
}

run_ldap_replicator() {
    python /app/scripts/ldap_replicator.py &
}

# ==========
# ENTRYPOINT
# ==========

mkdir -p /opt/opendj/locks

export JAVA_VERSION=$(java -version 2>&1 | awk -F '[\"_]' 'NR==1{print $2}')

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && run_wait
    source scl_source enable python27 && run_entrypoint
    source scl_source enable python27 && run_ldap_peer
    source scl_source enable python27 && run_ldap_replicator
else
    run_wait
    run_entrypoint
    run_ldap_peer
    run_ldap_replicator
fi

# run OpenDJ server
exec /opt/opendj/bin/start-ds -N
