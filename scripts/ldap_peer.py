import logging
import logging.config
import struct
import fcntl
import json
import os
import socket

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import as_boolean

from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("ldap_peer")


def get_ip_addr(ifname):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except IOError:
        addr = ""
    return addr


def guess_host_addr():
    addr_interface = os.environ.get("GLUU_LDAP_ADDR_INTERFACE", "")
    advertise_addr = os.environ.get("GLUU_LDAP_ADVERTISE_ADDR", "")
    addr = advertise_addr or get_ip_addr(addr_interface) or socket.getfqdn()
    return addr


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
        logger.warn("Auto replication is disabled; skipping server registration")
        return

    manager = get_manager()
    server = guess_host_addr()

    # register current server for discovery
    register_ldap_peer(manager, server)


if __name__ == "__main__":
    main()
