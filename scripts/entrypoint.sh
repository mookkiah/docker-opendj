#!/bin/sh
set -e

mkdir -p /opt/opendj/locks

export JAVA_VERSION=$(java -version 2>&1 | awk -F[\"_] 'NR==1{print $2}')

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/scripts/wait_for.py --deps="config,secret"
else
    python /opt/scripts/wait_for.py --deps="config,secret"
fi

if [ ! -f /deploy/touched ]; then
    # backward-compat
    if [ -f /touched ]; then
        mv /touched /deploy/touched
    else
        if [ -f /etc/redhat-release ]; then
            source scl_source enable python27 && python /opt/scripts/entrypoint.py
        else
            python /opt/scripts/entrypoint.py
        fi
        touch /deploy/touched
    fi
fi

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/scripts/ldap_peer.py
else
    python /opt/scripts/ldap_peer.py
fi

exec /opt/opendj/bin/start-ds -N
