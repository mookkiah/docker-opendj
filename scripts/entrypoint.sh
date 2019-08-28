#!/bin/sh
set -e

cat << LICENSE_ACK

# ================================================================================================ #
# Gluu License Agreement: https://github.com/GluuFederation/enterprise-edition/blob/4.0.0/LICENSE. #
# The use of Gluu Server Enterprise Edition is subject to the Gluu Support License.                #
# ================================================================================================ #

LICENSE_ACK

# check persistence type
case "${GLUU_PERSISTENCE_TYPE}" in
    ldap|hybrid)
        ;;
    *)
        echo "unsupported GLUU_PERSISTENCE_TYPE value; please choose 'ldap' or 'hybrid'"
        exit 1
        ;;
esac

# check mapping used by ldap
if [ "${GLUU_PERSISTENCE_TYPE}" = "hybrid" ]; then
    case "${GLUU_PERSISTENCE_LDAP_MAPPING}" in
        default|user|cache|site|statistic|authorization|token|client)
            ;;
        *)
            echo "unsupported GLUU_PERSISTENCE_LDAP_MAPPING value; please choose 'default', 'user', 'cache', 'site', 'statistic', 'authorization', 'token', or 'client'"
            exit 1
            ;;
    esac
fi

# run wait_for functions
deps="config,secret"
if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && gluu-wait --deps="$deps"
else
    gluu-wait --deps="$deps"
fi

# run Python entrypoint
mkdir -p /opt/opendj/locks

export JAVA_VERSION=$(java -version 2>&1 | awk -F[\"_] 'NR==1{print $2}')

if [ ! -f /deploy/touched ]; then
    # backward-compat
    if [ -f /touched ]; then
        mv /touched /deploy/touched
    else
        if [ -f /etc/redhat-release ]; then
            source scl_source enable python27 && python /app/scripts/entrypoint.py
        else
            python /app/scripts/entrypoint.py
        fi
        touch /deploy/touched
    fi
fi

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/ldap_peer.py
    source scl_source enable python27 && python /app/scripts/ldap_replicator.py &
else
    python /app/scripts/ldap_peer.py
    python /app/scripts/ldap_replicator.py &
fi

# run OpenDJ server
exec /opt/opendj/bin/start-ds -N
