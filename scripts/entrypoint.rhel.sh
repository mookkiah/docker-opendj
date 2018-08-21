#!/bin/sh
set -e

mkdir -p /opt/opendj/locks

if [ ! -f /touched ]; then
    source scl_source enable python27 && python /opt/scripts/entrypoint.py
    touch /touched
fi

exec /opt/opendj/bin/start-ds -N
