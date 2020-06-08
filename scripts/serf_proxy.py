#!/usr/bin/env python3
import logging
import logging.handlers
import os
import socket
import sys
import time
from collections import defaultdict

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import decode_text

logger = logging.getLogger("serf_proxy")
h = logging.handlers.RotatingFileHandler('/var/log/serf_proxy.log')
f = logging.Formatter('%(asctime)s %(name)s %(levelname)-8s %(message)s')
h.setFormatter(f)
logger.addHandler(h)
logger.setLevel(logging.INFO)


class Proxy:
    def __init__(self):
        self.handlers = {}

    def add_handler(self, role, handler):
        self.handlers[role] = handler

    def dispatch_event(self):
        if os.environ.get('SERF_EVENT') == 'user':
            event = os.environ['SERF_USER_EVENT']
        elif os.environ.get('SERF_EVENT') == 'query':
            event = os.environ['SERF_QUERY_NAME']
        else:
            event = os.environ.get("SERF_EVENT", "").replace('-', '_')
        event = f"on_{event}"

        role = os.environ.get('SERF_TAG_ROLE') or os.environ.get('SERF_SELF_ROLE')
        handler = self.handlers.get(role)

        if not handler:
            logger.warning(f"Handler for role {role} and event {event} is not available")
            return

        callback = getattr(handler, event)
        if not callable(callback):
            logger.warning(f"Handler {callback} for role {role} and event {event} is not callable")
            return

        _ = callback()


class BaseHandler:
    def __init__(self, manager):
        self._host = None
        self.manager = manager

    @property
    def host(self):
        if not self._host:
            self._host = socket.getfqdn()
        return self._host

    def _payload_from_stdin(self):
        for line in sys.stdin:
            yield line.strip("\n").split("\t")


class LDAPHandler(BaseHandler):
    def __init__(self, manager):
        super(LDAPHandler, self).__init__(manager)
        self.ldap_user = manager.config.get("ldap_binddn")
        self.ldap_password = decode_text(
            manager.secret.get("encoded_ox_ldap_pw"),
            manager.secret.get("encoded_salt"),
        ).decode()

    def guess_host_addr(self):
        advertise_addr = os.environ.get("GLUU_LDAP_ADVERTISE_ADDR", "")
        addr = advertise_addr or socket.getfqdn()
        return addr

    def get_ldap_peers(self):
        import json

        peers = json.loads(self.manager.config.get("ldap_peers", "{}"))
        if isinstance(peers, list):
            peers = {peer: peer for peer in peers}
        return peers

    def register(self):
        server = self.guess_host_addr()
        peers = self.get_ldap_peers()
        peers[server] = socket.getfqdn()
        self.manager.config.set("ldap_peers", peers)

    def unregister(self):
        server = self.guess_host_addr()
        peers = self.get_ldap_peers()
        logger.info("REGISTERING")
        logger.info(peers)
        peers.pop(server, None)
        logger.info(peers)
        self.manager.config.set("ldap_peers", peers)

    def on_member_join(self):
        for payload in self._payload_from_stdin():
            if payload[0] == self.host:
                continue

            logger.info(f"A member {payload[0]}/{payload[1]} is joined")
            source, dest = payload[0], self.host
            self.setup_replication(source, dest)

    def on_member_leave(self):
        for payload in self._payload_from_stdin():
            if payload[0] == self.host:
                continue
            logger.info(f"A member {payload[0]}/{payload[1]} is left")
            source, dest = payload[0], self.host
            self.teardown_replication(source, dest)

    def on_member_failed(self):
        for payload in self._payload_from_stdin():
            if payload[0] == self.host:
                continue
            logger.info(f"A member {payload[0]}/{payload[1]} is failed")
            source, dest = payload[0], self.host
            self.teardown_replication(source, dest)

    def get_ldap_status(self, bind_dn, password):
        cmd = "/opt/opendj/bin/status -D '{}' -w '{}' --connectTimeout 10000".format(
            bind_dn, password,
        )
        out, err, code = exec_cmd(cmd)
        return out.strip(), err.strip(), code

    def check_required_entry(self, host, user, password, base_dn):
        """Checks if entry is exist.
        """
        port = 1636

        if base_dn == "o=metric":
            dn = "ou=statistic,o=metric"
        elif base_dn == "o=site":
            dn = "ou=cache-refresh,o=site"
        else:
            passport_rp_client_id = self.manager.config.get("passport_rp_client_id")
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

    def get_datasources(self, user, password, non_repl_only=True):
        """Get backends.
        """
        # get status from LDAP server
        interval = 10
        while True:
            out, _, code = self.get_ldap_status(user, password)
            if code != 0:
                logger.warning(
                    f"Unable to get status from LDAP server; reason={out.decode()}; "
                    f"retrying in {interval} seconds"
                )
                time.sleep(interval)
                continue
            break

        if code != 0:
            logger.error(f"Unable to get LDAP status; reason={out.decode()}")
            sys.exit(1)

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

    def replicate_from(self, peer, server, base_dn):
        """Configure replication between 2 LDAP servers.
        """
        ldaps_port = 1636
        GLUU_ADMIN_PORT = os.environ.get("GLUU_ADMIN_PORT", 4444)
        GLUU_REPLICATION_PORT = os.environ.get("GLUU_REPLICATION_PORT", 8989)

        # enable replication for specific backend
        logger.info("Enabling OpenDJ replication of {} between {}:{} and {}:{}.".format(
            base_dn, peer, ldaps_port, server, ldaps_port,
        ))

        enable_cmd = " ".join([
            "/opt/opendj/bin/dsreplication",
            "enable",
            "--host1 {}".format(peer),
            "--port1 {}".format(GLUU_ADMIN_PORT),
            "--bindDN1 '{}'".format(self.ldap_user),
            "--bindPassword1 {}".format(self.ldap_password),
            "--replicationPort1 {}".format(GLUU_REPLICATION_PORT),
            "--secureReplication1",
            "--host2 {}".format(server),
            "--port2 {}".format(GLUU_ADMIN_PORT),
            "--bindDN2 '{}'".format(self.ldap_user),
            "--bindPassword2 {}".format(self.ldap_password),
            "--secureReplication2",
            "--adminUID admin",
            "--adminPassword {}".format(self.ldap_password),
            "--baseDN '{}'".format(base_dn),
            "-X",
            "-n",
            "-Q",
            "--trustAll",
        ])

        logger.info(enable_cmd)
        _, err, code = exec_cmd(enable_cmd)
        if code:
            logger.warning(err.decode().strip())

        # initialize replication for specific backend
        logger.info("Initializing OpenDJ replication of {} between {}:{} and {}:{}.".format(
            base_dn, peer, ldaps_port, server, ldaps_port,
        ))

        init_cmd = " ".join([
            "/opt/opendj/bin/dsreplication",
            "initialize",
            "--baseDN '{}'".format(base_dn),
            "--adminUID admin",
            "--adminPassword {}".format(self.ldap_password),
            "--hostSource {}".format(peer),
            "--portSource {}".format(GLUU_ADMIN_PORT),
            "--hostDestination {}".format(server),
            "--portDestination {}".format(GLUU_ADMIN_PORT),
            "-X",
            "-n",
            "-Q",
            "--trustAll",
        ])
        logger.info(init_cmd)
        _, err, code = exec_cmd(init_cmd)
        if code:
            logger.warning(err.decode().strip())

    def setup_replication(self, source, dest):
        logger.info(f"Setup replication from {source} to {dest} (if needed)")
        datasources = self.get_datasources(self.ldap_user, self.ldap_password)

        # if there's no backend that need to be replicated, skip the rest of the process;
        # note, in some cases the Generation ID will be different due to mismatched data structure
        # to fix this issue we can re-init replication manually; please refer to
        # https://backstage.forgerock.com/knowledge/kb/article/a36616593 for details
        if not datasources:
            logger.info("All required backends have been replicated")
            sys.exit(0)

        logger.info(datasources)

        for dn, _ in datasources.items():
            _, err, code = self.check_required_entry(
                source, self.ldap_user, self.ldap_password, dn,
            )
            if code != 0:
                logger.warning(
                    f"Unable to get required entry at LDAP server {source}:1636; "
                    f"reason={err.decode()}"
                )
                continue

            # replicate from server that has data; note: can't assume the
            # whole replication process is succeed, hence subsequence checks
            # will be executed
            self.replicate_from(source, dest, dn)

    def teardown_replication(self, source, dest):
        logger.info(f"Teardown replication from {source} to {dest} (if needed)")


if __name__ == '__main__':
    if not as_boolean(os.environ.get("GLUU_SERF_MEMBERSHIP", False)):
        sys.exit(0)

    manager = get_manager()
    proxy = Proxy()
    proxy.add_handler("ldap", LDAPHandler(manager))
    proxy.dispatch_event()
