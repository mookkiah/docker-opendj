#!/bin/sh
set -e

mkdir -p /opt/opendj/locks

export JAVA_VERSION=$(java -version 2>&1 | awk -F[\"_] 'NR==1{print $2}')

if [ ! -f /deploy/touched ]; then
    if [ -f /etc/redhat-release ]; then
        source scl_source enable python27 && python /opt/scripts/entrypoint.py
    else
        python /opt/scripts/entrypoint.py
    fi
    touch /deploy/touched
fi

exec /opt/opendj/bin/start-ds -N
