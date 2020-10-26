import contextlib
import logging
import logging.config
import os
import time
import socket
from collections import defaultdict

from jans.pycloudlib import get_manager
from jans.pycloudlib.utils import exec_cmd
from jans.pycloudlib.utils import as_boolean

from settings import LOGGING_CONFIG

DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("ldap_replicator")

manager = get_manager()


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


def replicate_from(peer, server, base_dn):
    """Configure replication between 2 LDAP servers.
    """
    admin_port = os.environ.get("CN_ADMIN_PORT", 4444)
    repl_port = os.environ.get("CN_REPLICATION_PORT", 8989)

    ldap_binddn = manager.config.get("ldap_binddn")

    with admin_password_bound(manager) as password_file:
        # enable replication for specific backend
        logger.info(f"Enabling OpenDJ replication of {base_dn} between {peer} and {server}.")

        enable_cmd = " ".join([
            "/opt/opendj/bin/dsreplication",
            "enable",
            f"--host1 {peer}",
            f"--port1 {admin_port}",
            f"--bindDN1 '{ldap_binddn}'",
            f"--bindPasswordFile1 {password_file}",
            f"--replicationPort1 {repl_port}",
            "--secureReplication1",
            f"--host2 {server}",
            f"--port2 {admin_port}",
            f"--bindDN2 '{ldap_binddn}'",
            f"--bindPasswordFile2 {password_file}",
            "--secureReplication2",
            "--adminUID admin",
            f"--adminPasswordFile {password_file}",
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
            f"--adminPasswordFile {password_file}",
            f"--hostSource {peer}",
            f"--portSource {admin_port}",
            f"--hostDestination {server}",
            f"--portDestination {admin_port}",
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
        client_id = manager.config.get('oxauth_client_id')
        dn = f"inum={client_id},ou=clients,{base_dn}"

    with admin_password_bound(manager) as password_file:
        cmd = " ".join([
            "/opt/opendj/bin/ldapsearch",
            f"--hostname {host}",
            f"--port {port}",
            f"--baseDN '{dn}'",
            f"--bindDN '{user}'",
            f"--bindPasswordFile {password_file}",
            "-Z",
            "-X",
            "--searchScope base",
            "'(objectClass=*)' 1.1",
        ])
        out, err, code = exec_cmd(cmd)
        return out.strip(), err.strip(), code


def get_ldap_status(bind_dn):
    with admin_password_bound(manager) as password_file:
        cmd = f"/opt/opendj/bin/status -D '{bind_dn}' --bindPasswordFile {password_file} --connectTimeout 10000"
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
                f"retrying in {interval} seconds"  # noqa: C812
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
    #    Base DN:                      o=jans
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
    #        "o=jans": {"replicated": True, "entries": 1},
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

    # base_dn = os.environ.get("CN_LDAP_BASE_DN", "o=jans")
    base_dn = "o=jans"

    datasources = {
        k: v for k, v in datasources.items()
        if k in (base_dn, "o=site", "o=metric")
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
        interval = int(os.environ.get("CN_LDAP_REPL_CHECK_INTERVAL", 10))
        if interval < 1:
            interval = 10
    except TypeError:
        interval = 10
    return interval


def get_repl_max_retries():
    try:
        max_retries = int(os.environ.get("CN_LDAP_REPL_MAX_RETRIES", 30))
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
    auto_repl = as_boolean(os.environ.get("CN_LDAP_AUTO_REPLICATE", True))
    if not auto_repl:
        logger.warning("Auto replication is disabled; skipping replication check")
        return

    server = socket.getfqdn()
    ldaps_port = manager.config.get("ldaps_port")
    ldap_user = manager.config.get("ldap_binddn")

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
                return

            for dn, _ in datasources.items():
                _, err, code = check_required_entry(
                    peer, ldaps_port, ldap_user, dn,
                )
                if code != 0:
                    logger.warning(
                        f"Unable to get required entry at LDAP server {peer}:1636; "
                        f"reason={err.decode()}"  # noqa: C812
                    )
                    continue

                # replicate from server that has data; note: can't assume the
                # whole replication process is succeed, hence subsequence checks
                # will be executed
                replicate_from(peer, server, dn)

        # delay between next check
        time.sleep(interval)
        retry += 1


if __name__ == "__main__":
    main()
