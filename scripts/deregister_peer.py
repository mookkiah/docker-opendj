import contextlib
import json
import logging.config
import os
import socket

from jans.pycloudlib import get_manager
from jans.pycloudlib.utils import exec_cmd

from settings import LOGGING_CONFIG

DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("ldap_peer")


@contextlib.contextmanager
def admin_password_bound(manager, password_file=DEFAULT_ADMIN_PW_PATH):
    if not os.path.isfile(password_file):
        manager.secret.to_file(
            "encoded_ox_ldap_pw", password_file, decode=True,
        )

    try:
        yield password_file
    except Exception:
        raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(password_file)


def get_ldap_peers(manager):
    return json.loads(manager.config.get("ldap_peers", "[]"))


def deregister_ldap_peer(manager, hostname):
    peers = set(get_ldap_peers(manager))

    try:
        peers.remove(hostname)
        manager.config.set("ldap_peers", list(peers))
    except KeyError:
        pass


def main():
    manager = get_manager()
    server = socket.getfqdn()

    deregister_ldap_peer(manager, server)

    with admin_password_bound(manager) as password_file:
        cmd = " ".join([
            "/opt/opendj/bin/dsreplication",
            "disable",
            "--disableAll",
            "--port 4444",
            f"--hostname {server}",
            "--adminUID admin",
            f"--adminPasswordFile {password_file}",
            "-X",
            "-n",
            "-Q",
        ])
        out, err, code = exec_cmd(cmd)

        if code:
            err = err or out
            logger.warning(f"Unable to disable replication for current server; reason={err.decode()}")


if __name__ == "__main__":
    main()
