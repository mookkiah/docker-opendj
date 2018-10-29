#!/bin/sh
set -e

mkdir -p /opt/opendj/locks

if [ ! -f /deploy/touched ]; then
    if [ -f /etc/redhat-release ]; then
        source scl_source enable python27 && python /opt/scripts/entrypoint.py
    else
        python /opt/scripts/entrypoint.py
    fi
    touch /deploy/touched
fi

exec /opt/opendj/bin/start-ds -N
