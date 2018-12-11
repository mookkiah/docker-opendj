#!/bin/sh
set -e

mkdir -p /opt/opendj/locks

export JAVA_VERSION=$(java -version 2>&1 | awk -F[\"_] 'NR==1{print $2}')

if [ ! -f /touched ]; then
    python /opt/scripts/entrypoint.py
    touch /touched
fi

exec /opt/opendj/bin/start-ds -N
