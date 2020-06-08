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


def get_ip_addr(ifname: str) -> str:
    """Get IP address bind to an interface.

    :param ifname: Interface name, i.e. ``eth0``
    :return: IP address of interface otherwise empty string
    :rtype: str
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode())
        )[20:24])
    except (IOError, OSError):
        addr = ""
    return addr


def guess_host_addr():
    advertise_addr = os.environ.get("GLUU_LDAP_ADVERTISE_ADDR", "")
    addr = advertise_addr or socket.getfqdn()
    return addr


def get_ldap_peers(manager):
    peers = json.loads(manager.config.get("ldap_peers", "{}"))
    if isinstance(peers, list):
        peers = {peer: peer for peer in peers}
    return peers


def register_ldap_peer(manager):
    server = guess_host_addr()
    peers = get_ldap_peers(manager)
    peers[server] = socket.getfqdn()
    manager.config.set("ldap_peers", peers)


def main():
    auto_repl = as_boolean(os.environ.get("GLUU_LDAP_AUTO_REPLICATE", True))
    if not auto_repl:
        logger.warning("Auto replication is disabled; skipping server registration")
        return

    # register current server for discovery
    manager = get_manager()
    register_ldap_peer(manager)


if __name__ == "__main__":
    if not as_boolean(os.environ.get("GLUU_SERF_MEMBERSHIP", False)):
        main()
