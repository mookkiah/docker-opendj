import logging
import logging.config
import json
import os
import socket

from jans.pycloudlib import get_manager
from jans.pycloudlib.utils import as_boolean
from jans.pycloudlib.utils import exec_cmd

from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("register_peer")


def guess_host_addr():
    return socket.getfqdn()


def get_ldap_peers(manager):
    return json.loads(manager.config.get("ldap_peers", "[]"))


def register_ldap_peer(manager, hostname):
    peers = set(get_ldap_peers(manager))
    # add new hostname
    peers.add(hostname)
    manager.config.set("ldap_peers", list(peers))


def main():
    auto_repl = as_boolean(os.environ.get("CN_LDAP_AUTO_REPLICATE", True))
    if not auto_repl:
        logger.warning("Auto replication is disabled; skipping server registration")
        return

    manager = get_manager()
    server = guess_host_addr()

    # register current server for discovery
    register_ldap_peer(manager, server)

    mcast = as_boolean(os.environ.get("CN_SERF_MULTICAST_DISCOVER", False))
    if mcast:
        return

    peers = [peer for peer in get_ldap_peers(manager) if peer != server]

    for peer in peers:
        out, err, code = exec_cmd(f"serf join {peer}")

        if not code:
            break

        err = err or out
        logger.warning(f"Unable to join Serf cluster via {peer}; reason={err}")


if __name__ == "__main__":
    main()
