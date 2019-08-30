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

GLUU_ADMIN_PORT = os.environ.get("GLUU_ADMIN_PORT", 4444)
GLUU_REPLICATION_PORT = os.environ.get("GLUU_REPLICATION_PORT", 8989)

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("ldap_replicator")

manager = get_manager()


def replicate_from(peer, server, base_dn):
    passwd = decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                         manager.secret.get("encoded_salt"))

    ldaps_port = manager.config.get("ldaps_port")

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


def check_base_dn(host, port, dn):
    passwd = decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                         manager.secret.get("encoded_salt"))

    cmd = " ".join([
        "/opt/opendj/bin/ldapsearch",
        "--hostname {}".format(host),
        "--port {}".format(port),
        "--baseDN '{}'".format(dn),
        "--bindDN '{}'".format(manager.config.get("ldap_binddn")),
        "--bindPassword {}".format(passwd),
        "-Z",
        "-X",
        "--searchScope base",
        "'(objectclass=*)' 1.1",
    ])
    out, err, code = exec_cmd(cmd)
    return out.strip(), err.strip(), code


def get_datasources(sources):
    for index, line in enumerate(sources):
        if line.find("--- Data Sources ---") > 0:
            src_index = index + 1
            break

    datasources = defaultdict(dict)
    dn, repl = "", {}

    for src in sources[src_index:]:
        if src.startswith("Base DN"):
            dn = src.split(":")[-1].strip()
            datasources[dn] = {}

        if src.startswith("Replication"):
            repl = src.split(":")[-1].strip()
            status = bool(repl.lower() == "enabled")
            datasources[dn] = {"replicated": status}

    return datasources


def main():
    server = guess_host_addr()
    ldaps_port = manager.config.get("ldaps_port")

    try:
        interval = int(os.environ.get("GLUU_LDAP_REPL_CHECK_INTERVAL", 10))
    except TypeError:
        interval = 10

    if interval < 1:
        interval = 10

    while True:
        # check if replication has been enabled
        cmd = "/opt/opendj/bin/status -D '{}' -w '{}' --connectTimeout 10000".format(
            manager.config.get("ldap_binddn"),
            decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                        manager.secret.get("encoded_salt")),
        )
        out, _, code = exec_cmd(cmd)

        if code != 0:
            logger.warn("Unable to check replication status; reason={}; "
                        "retrying in {} seconds".format(out.strip(), interval))
            time.sleep(interval)
            continue

        datasources = {
            k: v for k, v in get_datasources(out.splitlines()).iteritems()
            if v["replicated"] is False
        }

        # no empty db
        if not datasources:
            logger.info("All databases have been populated")
            break

        for peer in get_ldap_peers(manager):
            # skip if peer is current server
            if peer == server:
                continue

            for dn, repl in datasources.iteritems():
                # skip if already replicated
                if repl["replicated"]:
                    continue

                _, err, code = check_base_dn(peer, ldaps_port, dn)
                if code != 0:
                    logger.warn("Unable to check base DN {} at LDAP server {}:1636; "
                                "reason={}".format(dn, peer, err))
                    continue

                # replicate from server that has data
                replicate_from(peer, server, dn)

        # delay between next check
        time.sleep(interval)


if __name__ == "__main__":
    main()
