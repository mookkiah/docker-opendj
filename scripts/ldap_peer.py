import struct
import fcntl
import json
import os
import socket

from gluulib import get_manager


GLUU_LDAP_ADDR_INTERFACE = os.environ.get("GLUU_LDAP_ADDR_INTERFACE", "")
GLUU_LDAP_ADVERTISE_ADDR = os.environ.get("GLUU_LDAP_ADVERTISE_ADDR", "")


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
    addr = GLUU_LDAP_ADVERTISE_ADDR or get_ip_addr(GLUU_LDAP_ADDR_INTERFACE) or socket.getfqdn()
    return addr


def get_ldap_peers(manager):
    return json.loads(manager.config.get("ldap_peers", "[]"))


def register_ldap_peer(manager, hostname):
    peers = set(get_ldap_peers(manager))
    # add new hostname
    peers.add(hostname)
    manager.config.set("ldap_peers", list(peers))


def migrate_ldap_servers(manager):
    # migrate ``ldap_servers`` to ``ldap_peers``
    adapter = os.environ.get("GLUU_CONFIG_ADAPTER", "")

    if adapter != "consul":
        return

    # make unique peers
    peers = set([])

    for _, server in manager.config.adapter.find("ldap_servers").iteritems():
        peer = json.loads(server)
        peers.add(peer["host"])

    if peers:
        # convert set to list to satisfy ``manager.config.set``
        manager.config.set("ldap_peers", list(peers))


if __name__ == "__main__":
    manager = get_manager()
    server = guess_host_addr()

    # register current server for discovery
    register_ldap_peer(manager, server)
