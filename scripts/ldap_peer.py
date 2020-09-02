import logging
import logging.config
# import struct
# import fcntl
import json
import os
import socket

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.utils import exec_cmd

from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("ldap_peer")


# def get_ip_addr(ifname):
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         addr = socket.inet_ntoa(fcntl.ioctl(
#             sock.fileno(),
#             0x8915,  # SIOCGIFADDR
#             struct.pack('256s', ifname[:15])
#         )[20:24])
#     except IOError:
#         addr = ""
#     return addr


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
    auto_repl = as_boolean(os.environ.get("GLUU_LDAP_AUTO_REPLICATE", True))
    if not auto_repl:
        logger.warning("Auto replication is disabled; skipping server registration")
        return

    manager = get_manager()
    server = guess_host_addr()

    # register current server for discovery
    register_ldap_peer(manager, server)

    mcast = as_boolean(os.environ.get("GLUU_SERF_MULTICAST_DISCOVER", False))
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
