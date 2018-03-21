#!/bin/sh
set -e

mkdir -p /opt/opendj/locks

if [ ! -f /touched ]; then
    python /opt/scripts/entrypoint.py
    touch /touched
fi

exec /opt/opendj/bin/start-ds -N
