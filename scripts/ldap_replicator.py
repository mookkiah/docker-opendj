import logging
import logging.config
import os
import time
from collections import defaultdict

from ldap_peer import get_ldap_peers
from ldap_peer import guess_host_addr
from settings import LOGGING_CONFIG

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import as_boolean

GLUU_ADMIN_PORT = os.environ.get("GLUU_ADMIN_PORT", 4444)
GLUU_REPLICATION_PORT = os.environ.get("GLUU_REPLICATION_PORT", 8989)

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("ldap_replicator")

manager = get_manager()


def replicate_from(peer, server, base_dn):
    """Configure replication between 2 LDAP servers.
    """
    passwd = decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                         manager.secret.get("encoded_salt"))

    ldaps_port = manager.config.get("ldaps_port")

    # enable replication for specific backend
    logger.info("Enabling OpenDJ replication of {} between {}:{} and {}:{}.".format(
        base_dn, peer, ldaps_port, server, ldaps_port,
    ))

    enable_cmd = " ".join([
        "/opt/opendj/bin/dsreplication",
        "enable",
        "--host1 {}".format(peer),
        "--port1 {}".format(GLUU_ADMIN_PORT),
        "--bindDN1 '{}'".format(manager.config.get("ldap_binddn")),
        "--bindPassword1 {}".format(passwd),
        "--replicationPort1 {}".format(GLUU_REPLICATION_PORT),
        "--secureReplication1",
        "--host2 {}".format(server),
        "--port2 {}".format(GLUU_ADMIN_PORT),
        "--bindDN2 '{}'".format(manager.config.get("ldap_binddn")),
        "--bindPassword2 {}".format(passwd),
        "--secureReplication2",
        "--adminUID admin",
        "--adminPassword {}".format(passwd),
        "--baseDN '{}'".format(base_dn),
        "-X",
        "-n",
        "-Q",
        "--trustAll",
    ])
    _, err, code = exec_cmd(enable_cmd)
    if code:
        logger.warn(err.strip())

    # initialize replication for specific backend
    logger.info("Initializing OpenDJ replication of {} between {}:{} and {}:{}.".format(
        base_dn, peer, ldaps_port, server, ldaps_port,
    ))

    init_cmd = " ".join([
        "/opt/opendj/bin/dsreplication",
        "initialize",
        "--baseDN '{}'".format(base_dn),
        "--adminUID admin",
        "--adminPassword {}".format(passwd),
        "--hostSource {}".format(peer),
        "--portSource {}".format(GLUU_ADMIN_PORT),
        "--hostDestination {}".format(server),
        "--portDestination {}".format(GLUU_ADMIN_PORT),
        "-X",
        "-n",
        "-Q",
        "--trustAll",
    ])
    _, err, code = exec_cmd(init_cmd)
    if code:
        logger.warn(err.strip())


def check_required_entry(host, port, user, password, base_dn):
    """Checks if entry is exist.
    """
    if base_dn == "o=metric":
        dn = "ou=statistic,o=metric"
    elif base_dn == "o=site":
        dn = "ou=cache-refresh,o=site"
    else:
        passport_rp_client_id = manager.config.get("passport_rp_client_id")
        dn = "inum={},ou=clients,o=gluu".format(passport_rp_client_id)

    cmd = " ".join([
        "/opt/opendj/bin/ldapsearch",
        "--hostname {}".format(host),
        "--port {}".format(port),
        "--baseDN '{}'".format(dn),
        "--bindDN '{}'".format(user),
        "--bindPassword {}".format(password),
        "-Z",
        "-X",
        "--searchScope base",
        "'(objectClass=*)' 1.1",
    ])
    out, err, code = exec_cmd(cmd)
    return out.strip(), err.strip(), code


def get_ldap_status(bind_dn, password):
    cmd = "/opt/opendj/bin/status -D '{}' -w '{}' --connectTimeout 10000".format(
        bind_dn, password,
    )
    out, err, code = exec_cmd(cmd)
    return out.strip(), err.strip(), code


def get_datasources(user, password, interval, non_repl_only=True):
    """Get backends.
    """
    # get status from LDAP server
    while True:
        out, _, code = get_ldap_status(user, password)
        if code != 0:
            logger.warn("Unable to get status from LDAP server; reason={}; "
                        "retrying in {} seconds".format(out, interval))
            time.sleep(interval)
            continue
        break

    sources = out.splitlines()
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
        k: v for k, v in datasources.iteritems()
        if k in ("o=gluu", "o=site", "o=metric")
    }

    if non_repl_only:
        datasources = {
            k: v for k, v in datasources.iteritems()
            if any([v["repl_enabled"] is False,
                    v["entries"] == 0])
        }
    return datasources


def get_repl_interval():
    try:
        interval = int(os.environ.get("GLUU_LDAP_REPL_CHECK_INTERVAL", 10))
    except TypeError:
        interval = 10
    return max(1, interval)


def main():
    auto_repl = as_boolean(os.environ.get("GLUU_LDAP_AUTO_REPLICATE", True))
    if not auto_repl:
        logger.warn("Auto replication is disabled; skipping replication check")
        return

    server = guess_host_addr()
    ldaps_port = manager.config.get("ldaps_port")
    ldap_user = manager.config.get("ldap_binddn")
    ldap_password = decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                                manager.secret.get("encoded_salt"))
    interval = get_repl_interval()

    while True:
        peers = [peer for peer in get_ldap_peers(manager) if peer != server]

        for peer in peers:
            logger.info("Checking replicated backends")

            datasources = get_datasources(ldap_user, ldap_password, interval)

            # if there's no backend that need to be replicated, skip the rest of the process;
            # note, in some cases the Generation ID will be different due to mismatched data structure
            # to fix this issue we can re-init replication manually; please refer to
            # https://backstage.forgerock.com/knowledge/kb/article/a36616593 for details
            if not datasources:
                logger.info("All required backends have been replicated")
                return

            for dn, _ in datasources.iteritems():
                _, err, code = check_required_entry(
                    peer, ldaps_port, ldap_user, ldap_password, dn,
                )
                if code != 0:
                    logger.warn("Unable to get required entry at LDAP server {}:1636; "
                                "reason={}".format(peer, err))
                    continue

                # replicate from server that has data; note: can't assume the
                # whole replication process is succeed, hence subsequence checks
                # will be executed
                replicate_from(peer, server, dn)

        # delay between next check
        time.sleep(interval)


if __name__ == "__main__":
    main()
