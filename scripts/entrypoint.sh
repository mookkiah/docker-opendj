#!/bin/sh
set -e

if [ ! -f /touched ]; then
    python /opt/scripts/entrypoint.py
    # stop opendj instance (if any) to avoid conflict on starting the actual server
    /opt/opendj/bin/stop-ds --quiet >>/dev/null
    touch /touched
fi

exec /opt/opendj/bin/start-ds -N
