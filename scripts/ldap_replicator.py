import contextlib
import logging
import logging.config
import os
import time
import socket
from collections import defaultdict

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import as_boolean

from settings import LOGGING_CONFIG

DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("ldap_replicator")

manager = get_manager()


def replicate_from(peer, server, base_dn):
    """Configure replication between 2 LDAP servers.
    """
    GLUU_ADMIN_PORT = os.environ.get("GLUU_ADMIN_PORT", 4444)
    GLUU_REPLICATION_PORT = os.environ.get("GLUU_REPLICATION_PORT", 8989)

    ldap_binddn = manager.config.get("ldap_binddn")

    # enable replication for specific backend
    logger.info(f"Enabling OpenDJ replication of {base_dn} between {peer} and {server}.")

    enable_cmd = " ".join([
        "/opt/opendj/bin/dsreplication",
        "enable",
        f"--host1 {peer}",
        f"--port1 {GLUU_ADMIN_PORT}",
        f"--bindDN1 '{ldap_binddn}'",
        f"--bindPasswordFile1 {DEFAULT_ADMIN_PW_PATH}",
        f"--replicationPort1 {GLUU_REPLICATION_PORT}",
        "--secureReplication1",
        f"--host2 {server}",
        f"--port2 {GLUU_ADMIN_PORT}",
        f"--bindDN2 '{ldap_binddn}'",
        f"--bindPasswordFile2 {DEFAULT_ADMIN_PW_PATH}",
        "--secureReplication2",
        "--adminUID admin",
        f"--adminPasswordFile {DEFAULT_ADMIN_PW_PATH}",
        f"--baseDN '{base_dn}'",
        "-X",
        "-n",
        "-Q",
    ])
    _, err, code = exec_cmd(enable_cmd)
    if code:
        logger.warning(err.decode().strip())

    # initialize replication for specific backend
    logger.info(f"Initializing OpenDJ replication of {base_dn} between {peer} and {server}.")

    init_cmd = " ".join([
        "/opt/opendj/bin/dsreplication",
        "initialize",
        f"--baseDN '{base_dn}'",
        "--adminUID admin",
        f"--adminPasswordFile {DEFAULT_ADMIN_PW_PATH}",
        f"--hostSource {peer}",
        f"--portSource {GLUU_ADMIN_PORT}",
        f"--hostDestination {server}",
        f"--portDestination {GLUU_ADMIN_PORT}",
        "-X",
        "-n",
        "-Q",
    ])
    _, err, code = exec_cmd(init_cmd)
    if code:
        logger.warning(err.decode().strip())


def check_required_entry(host, port, user, base_dn):
    """Checks if entry is exist.
    """
    if base_dn == "o=metric":
        dn = "ou=statistic,o=metric"
    elif base_dn == "o=site":
        dn = "ou=cache-refresh,o=site"
    else:
        passport_rp_client_id = manager.config.get("passport_rp_client_id")
        dn = f"inum={passport_rp_client_id},ou=clients,o=gluu"

    cmd = " ".join([
        "/opt/opendj/bin/ldapsearch",
        f"--hostname {host}",
        f"--port {port}",
        f"--baseDN '{dn}'",
        f"--bindDN '{user}'",
        f"--bindPasswordFile {DEFAULT_ADMIN_PW_PATH}",
        "-Z",
        "-X",
        "--searchScope base",
        "'(objectClass=*)' 1.1",
    ])
    out, err, code = exec_cmd(cmd)
    return out.strip(), err.strip(), code


def get_ldap_status(bind_dn):
    cmd = f"/opt/opendj/bin/status -D '{bind_dn}' --bindPasswordFile {DEFAULT_ADMIN_PW_PATH} --connectTimeout 10000"
    out, err, code = exec_cmd(cmd)
    return out.strip(), err.strip(), code


def get_datasources(user, interval, non_repl_only=True):
    """Get backends.
    """
    # get status from LDAP server
    while True:
        out, _, code = get_ldap_status(user)
        if code != 0:
            logger.warning(
                f"Unable to get status from LDAP server; reason={out.decode()}; "
                f"retrying in {interval} seconds"
            )
            time.sleep(interval)
            continue
        break

    sources = out.decode().splitlines()
    src_index = 0

    # given sources as text:
    #
    #            --- Connection Handlers ---
    #    Address:Port : Protocol             : State
    #    -------------:----------------------:---------
    #    8989         : Replication (secure) : Enabled
    #    0.0.0.0:1636 : LDAPS                : Enabled
    #
    #            --- Data Sources ---
    #    Base DN:                      o=gluu
    #    Backend ID:                   userRoot
    #    Entries:                      174
    #    Replication:                  Enabled
    #    Missing Changes:              <not available>
    #    Age of Oldest Missing Change: <not available>
    #
    # parse the text to get backends and their status
    for index, line in enumerate(sources):
        if line.find("--- Data Sources ---") > 0:
            src_index = index + 1
            break

    datasources = defaultdict(dict)
    dn = ""

    # the result (if found) would be in the following structure, for example:
    #
    #    {
    #        "o=gluu": {"replicated": True, "entries": 1},
    #        "o=site": {"replicated": False, "entries": 0},
    #        "o=metric": {"replicated": True, "entries": 0},
    #    }
    for src in sources[src_index:]:
        if src.startswith("Base DN"):
            dn = src.split(":")[-1].strip()
            datasources[dn] = {}

        if src.startswith("Replication"):
            repl = src.split(":")[-1].strip()
            status = bool(repl.lower() == "enabled")
            datasources[dn]["repl_enabled"] = status

        if src.startswith("Entries"):
            entry_num = src.split(":")[-1].strip()
            datasources[dn]["entries"] = int(entry_num)

    datasources = {
        k: v for k, v in datasources.items()
        if k in ("o=gluu", "o=site", "o=metric")
    }

    if non_repl_only:
        datasources = {
            k: v for k, v in datasources.items()
            if any([v["repl_enabled"] is False,
                    v["entries"] == 0])
        }
    return datasources


def get_repl_interval():
    try:
        interval = int(os.environ.get("GLUU_LDAP_REPL_CHECK_INTERVAL", 10))
        if interval < 1:
            interval = 10
    except TypeError:
        interval = 10
    return interval


def get_repl_max_retries():
    try:
        max_retries = int(os.environ.get("GLUU_LDAP_REPL_MAX_RETRIES", 30))
        if max_retries < 1:
            max_retries = 30
    except TypeError:
        max_retries = 30
    return max_retries


def get_ldap_peers():
    out, err, code = exec_cmd("serf members -tag role=ldap -status=alive")
    if code != 0:
        err = err or out
        logger.warning(f"Unable to get peers; reason={err.decode()}")
        return []

    peers = []
    for line in out.decode().splitlines():
        peer = line.split()
        peers.append(peer[0])
    return peers


def main():
    auto_repl = as_boolean(os.environ.get("GLUU_LDAP_AUTO_REPLICATE", True))
    if not auto_repl:
        logger.warning("Auto replication is disabled; skipping replication check")
        return

    server = socket.getfqdn()
    ldaps_port = manager.config.get("ldaps_port")
    ldap_user = manager.config.get("ldap_binddn")

    if not os.path.isfile(DEFAULT_ADMIN_PW_PATH):
        manager.secret.to_file("encoded_ox_ldap_pw", DEFAULT_ADMIN_PW_PATH, decode=True)

    interval = get_repl_interval()
    max_retries = get_repl_max_retries()
    retry = 0

    while retry < max_retries:
        logger.info(f"Checking replicated backends (attempt {retry + 1})")

        peers = [peer for peer in get_ldap_peers() if peer != server]

        for peer in peers:
            datasources = get_datasources(ldap_user, interval)

            # if there's no backend that need to be replicated, skip the rest of the process;
            # note, in some cases the Generation ID will be different due to mismatched data structure
            # to fix this issue we can re-init replication manually; please refer to
            # https://backstage.forgerock.com/knowledge/kb/article/a36616593 for details
            if not datasources:
                logger.info("All required backends have been replicated")

                # cleanup
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(DEFAULT_ADMIN_PW_PATH)
                return

            for dn, _ in datasources.items():
                _, err, code = check_required_entry(
                    peer, ldaps_port, ldap_user, dn,
                )
                if code != 0:
                    logger.warning(
                        f"Unable to get required entry at LDAP server {peer}:1636; "
                        f"reason={err.decode()}"
                    )
                    continue

                # replicate from server that has data; note: can't assume the
                # whole replication process is succeed, hence subsequence checks
                # will be executed
                replicate_from(peer, server, dn)

        # delay between next check
        time.sleep(interval)
        retry += 1

    # cleanup
    with contextlib.suppress(FileNotFoundError):
        os.unlink(DEFAULT_ADMIN_PW_PATH)


if __name__ == "__main__":
    main()
