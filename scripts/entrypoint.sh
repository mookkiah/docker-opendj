#!/bin/sh
set -e

mkdir -p /opt/opendj/locks

export JAVA_VERSION=$(java -version 2>&1 | awk -F[\"_] 'NR==1{print $2}')

if [ ! -f /deploy/touched ]; then
    # backward-compat
    if [ -f /touched ]; then
        mv /touched /deploy/touched
    else
        python /opt/scripts/entrypoint.py
        touch /deploy/touched
    fi
fi

exec /opt/opendj/bin/start-ds -N
