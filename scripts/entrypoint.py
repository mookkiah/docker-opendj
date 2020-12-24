import json
import logging
import logging.config
import os
import pathlib
import shutil
import socket
import sys
from contextlib import contextmanager

import ldap3
import javaproperties
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.utils import generate_ssl_certkey

from settings import LOGGING_CONFIG

DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

manager = get_manager()

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")


def guess_host_addr():
    return socket.getfqdn()


def install_opendj():
    logger.info("Installing OpenDJ.")

    # 1) render opendj-setup.properties
    ctx = {
        "ldap_hostname": guess_host_addr(),
        "ldap_port": manager.config.get("ldap_port"),
        "ldaps_port": manager.config.get("ldaps_port"),
        "ldap_jmx_port": 1689,
        "ldap_admin_port": 4444,
        "opendj_ldap_binddn": manager.config.get("ldap_binddn"),
        "ldapPassFn": DEFAULT_ADMIN_PW_PATH,
        "ldap_backend_type": "je",
    }
    with open("/app/templates/opendj-setup.properties") as fr:
        content = fr.read() % ctx

        with open("/opt/opendj/opendj-setup.properties", "w") as fw:
            fw.write(content)

    # 2) run installer
    cmd = " ".join([
        "/opt/opendj/setup",
        "--no-prompt",
        "--cli",
        "--acceptLicense",
        "--propertiesFilePath /opt/opendj/opendj-setup.properties",
        "--usePkcs12keyStore /etc/certs/opendj.pkcs12",
        "--keyStorePassword {}".format(
            decode_text(manager.secret.get("encoded_ldapTrustStorePass"), manager.secret.get("encoded_salt")).decode()
        ),
        "--doNotStart",
    ])
    out, err, code = exec_cmd(cmd)
    if code and err:
        logger.warning(err.decode())

    if all([os.environ.get("JAVA_VERSION", "") >= "1.8.0",
            os.path.isfile("/opt/opendj/config/config.ldif")]):
        with open("/opt/opendj/config/java.properties", "a") as f:
            status_arg = "\nstatus.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true"

            max_ram_percentage = os.environ.get("GLUU_MAX_RAM_PERCENTAGE", "75.0")
            java_opts = os.environ.get("GLUU_JAVA_OPTIONS", "")
            repl_arg = f"\ndsreplication.java-args=-client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true -XX:+UseContainerSupport -XX:MaxRAMPercentage={max_ram_percentage} {java_opts}"

            args = "".join([status_arg, repl_arg])
            f.write(args)


def run_dsjavaproperties():
    _, err, code = exec_cmd("/opt/opendj/bin/dsjavaproperties")
    if code and err:
        logger.warning(err.decode())


def sync_ldap_pkcs12():
    dest = manager.config.get("ldapTrustStoreFn")
    manager.secret.to_file("ldap_pkcs12_base64", dest, decode=True, binary_mode=True)


def sync_ldap_certs():
    """Gets opendj.crt, opendj.key, and opendj.pem
    """
    manager.secret.to_file("ldap_ssl_cert", "/etc/certs/opendj.crt", decode=True)
    manager.secret.to_file("ldap_ssl_key", "/etc/certs/opendj.key", decode=True)
    manager.secret.to_file("ldap_ssl_cacert", "/etc/certs/opendj.pem", decode=True)


@contextmanager
def ds_context():
    """Ensures Directory Server are up and teardown at the end of the context.
    """

    cmd = "/opt/opendj/bin/status -D '{}' --bindPasswordFile {} --connectTimeout 10000".format(
        manager.config.get("ldap_binddn"),
        DEFAULT_ADMIN_PW_PATH,
    )
    out, _, code = exec_cmd(cmd)
    running = out.decode().startswith("Unable to connect to the server")

    if not running:
        exec_cmd("/opt/opendj/bin/start-ds")

    try:
        yield
    except Exception:
        raise
    finally:
        exec_cmd("/opt/opendj/bin/stop-ds --quiet")


def run_upgrade():
    # buildinfo = "3.0.1"
    # if is_wrends():
    buildinfo = "4.0.0"

    # check if we need to upgrade
    if os.path.isfile("/opt/opendj/config/buildinfo"):
        # example of buildinfo `3.0.1.c5ad2e4846d8aeb501ffdfe5ae2dfd35136dfa68`
        with open("/opt/opendj/config/buildinfo") as f:
            old_buildinfo = ".".join([
                num for num in f.read().split(".") if num.isdigit()
            ])

            if old_buildinfo < buildinfo:
                logger.info("Trying to upgrade OpenDJ server")

                # backup old buildinfo
                exec_cmd("cp /opt/opendj/config/buildinfo /opt/opendj/config/buildinfo-{}".format(old_buildinfo))
                _, err, retcode = exec_cmd("/opt/opendj/upgrade --acceptLicense")
                assert retcode == 0, "Failed to upgrade OpenDJ; reason={}".format(err.decode())

                # backup current buildinfo
                exec_cmd("cp /opt/opendj/config/buildinfo /opt/opendj/config/buildinfo-{}".format(buildinfo))


def require_site():
    persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
    ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

    if persistence_type == "ldap":
        return True
    if persistence_type == "hybrid" and ldap_mapping == "site":
        return True
    return False


def main():
    alt_name = os.environ.get("GLUU_CERT_ALT_NAME", "")

    # the plain-text admin password is not saved in KV storage,
    # but we have the encoded one
    manager.secret.to_file("encoded_ox_ldap_pw", DEFAULT_ADMIN_PW_PATH, decode=True)

    logger.info("Syncing OpenDJ certs.")
    sync_ldap_certs()
    sync_ldap_pkcs12()

    logger.info("Checking certificate's Subject Alt Name (SAN)")
    san = get_certificate_san("/etc/certs/opendj.crt")

    if alt_name not in san:
        logger.info("Re-generating OpenDJ certs with SAN support.")

        # add new alt name
        san.append(alt_name)
        regenerate_ldap_certs(extra_dns=san)

        # update secrets
        manager.secret.from_file("ldap_ssl_cert", "/etc/certs/opendj.crt", encode=True)
        manager.secret.from_file("ldap_ssl_key", "/etc/certs/opendj.key", encode=True)
        manager.secret.from_file("ldap_ssl_cacert", "/etc/certs/opendj.pem", encode=True)

        regenerate_ldap_pkcs12()
        # update secrets
        manager.secret.from_file(
            "ldap_pkcs12_base64",
            manager.config.get("ldapTrustStoreFn"),
            encode=True,
            binary_mode=True,
        )

    # update ldap_init_*
    manager.config.set("ldap_init_host", alt_name)
    manager.config.set("ldap_init_port", 1636)

    # do upgrade if required
    run_upgrade()

    # patch for https://bugs.openjdk.java.net/browse/JDK-8217094
    disable_tls13()

    # Below we will check if there is a `/opt/opendj/config/config.ldif` or
    # `/opt/opendj/config/schema` directory with files signalling that OpenDJ
    # has already been successfully deployed and will launch as expected.
    if not any([os.path.isfile("/opt/opendj/config/config.ldif"),
                os.path.isdir("/opt/opendj/config/schema")]):
        cleanup_config_dir()
        install_opendj()

        with ds_context():
            # if not is_wrends():
            #     run_dsjavaproperties()

            create_backends()
            configure_opendj()
            configure_opendj_indexes()

    # post-installation cleanup
    for f in [DEFAULT_ADMIN_PW_PATH, "/opt/opendj/opendj-setup.properties"]:
        try:
            os.unlink(f)
        except OSError:
            pass

    # prepare serf config
    configure_serf()


def regenerate_ldap_certs(extra_dns=None):
    suffix = "opendj"
    country_code = manager.config.get("country_code")
    state = manager.config.get("state")
    city = manager.config.get("city")
    org_name = manager.config.get("orgName")
    domain = manager.config.get("hostname")
    email = manager.config.get("admin_email")

    cert, key = generate_ssl_certkey(
        suffix,
        email,
        domain,
        org_name,
        country_code,
        state,
        city,
        extra_dns=extra_dns,
    )

    with open("/etc/certs/{}.pem".format(suffix), "w") as fw:
        with open(cert) as fr:
            ldap_ssl_cert = fr.read()

        with open(key) as fr:
            ldap_ssl_key = fr.read()

        ldap_ssl_cacert = "".join([ldap_ssl_cert, ldap_ssl_key])
        fw.write(ldap_ssl_cacert)


def regenerate_ldap_pkcs12():
    suffix = "opendj"
    passwd = manager.secret.get("ldap_truststore_pass")
    hostname = manager.config.get("hostname")

    # Convert key to pkcs12
    cmd = " ".join([
        "openssl",
        "pkcs12",
        "-export",
        "-inkey /etc/certs/{}.key".format(suffix),
        "-in /etc/certs/{}.crt".format(suffix),
        "-out /etc/certs/{}.pkcs12".format(suffix),
        "-name {}".format(hostname),
        "-passout pass:{}".format(passwd),
    ])
    _, err, retcode = exec_cmd(cmd)
    assert retcode == 0, "Failed to generate PKCS12 file; reason={}".format(err.decode())


def get_certificate_san(certpath) -> str:
    with open(certpath, "rb") as f:
        crt = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

    san_obj = crt.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans = [f"{name.value}" for name in san_obj.value]
    return sans


def cleanup_config_dir():
    if not os.path.exists("/opt/opendj/config"):
        return

    # When mounting certain volumes, OpenDJ installation will fail to install
    # as the mounted volume may have some residual information for some reason
    # (i.e. Amazon ElasticBlockStorage's "lost+found" directory). This only
    # occurs on the first installation. Otherwise the volume can be used as
    # a successfully deployed persistent disk.
    subtree = os.listdir("/opt/opendj/config")

    for obj in subtree:
        path = "/opt/opendj/config/{0}".format(obj)
        logger.warning(
            "Found {0} in '/opt/opendj/config/' volume mount. "
            "/opt/opendj/config should be empty for a successful "
            "installation.".format(path)
        )

        if obj != "lost+found":
            logger.warning(
                "{0} will not be removed. Please manually remove any "
                "data from the volume mount for /opt/opendj/config/.".format(path)
            )
            continue

        logger.info("Removing {0}".format(path))
        try:
            # delete directory
            shutil.rmtree(path)
        except OSError:
            # delete file
            os.unlink(path)
        except Exception as exc:
            # Unforeseen information in the config/ dir will be logged and
            # prompt the administrator to deal with their issue.
            logger.warning(exc)


def is_wrends():
    return os.path.isfile("/opt/opendj/lib/wrends.jar")


def configure_serf():
    def get_keygen():
        keygen = manager.secret.get("serf_gluu_ldap_key")
        if not keygen:
            out, _, _ = exec_cmd("serf keygen")
            keygen = out.decode().strip()
            manager.secret.set("serf_gluu_ldap_key", keygen)
        return keygen

    conf_fn = pathlib.Path("/etc/gluu/conf/serf.json")

    # skip if config exists
    if conf_fn.is_file():
        return

    conf = {
        "node_name": guess_host_addr(),
        "tags": {"role": "ldap"},
        # "discover": "gluu-ldap",
        "log_level": os.environ.get("GLUU_SERF_LOG_LEVEL", "warn"),
        "profile": os.environ.get("GLUU_SERF_PROFILE", "lan"),
        "encrypt_key": get_keygen(),
    }

    mcast = as_boolean(os.environ.get("GLUU_SERF_MULTICAST_DISCOVER", False))
    if mcast:
        conf["discover"] = "gluu-ldap"

    conf_fn.write_text(json.dumps(conf))


def configure_opendj_indexes():
    logger.info("Configuring indexes for available backends.")

    with open("/app/templates/index.json") as f:
        data = json.load(f)

    host = "localhost:1636"
    user = manager.config.get("ldap_binddn")
    password = decode_text(
        manager.secret.get("encoded_ox_ldap_pw"),
        manager.secret.get("encoded_salt")
    )

    ldap_server = ldap3.Server(host, 1636, use_ssl=True)

    backends = ["userRoot", "metric"]
    if require_site():
        backends.append("site")

    with ldap3.Connection(ldap_server, user, password) as conn:
        for attr_map in data:
            for backend in attr_map["backend"]:
                if backend not in backends:
                    continue

                dn = f"ds-cfg-attribute={attr_map['attribute']},cn=Index,ds-cfg-backend-id={backend},cn=Backends,cn=config"
                attrs = {
                    'objectClass': ['top', 'ds-cfg-backend-index'],
                    'ds-cfg-attribute': [attr_map['attribute']],
                    'ds-cfg-index-type': attr_map['index'],
                    'ds-cfg-index-entry-limit': ['4000']
                }

                conn.add(dn, attributes=attrs)
                if conn.result["description"] != "success":
                    logger.warning(conn.result["message"])


def create_backends():
    logger.info("Creating backends.")
    mods = [
        "create-backend --backend-name metric --set base-dn:o=metric --type je --set enabled:true --set db-cache-percent:10",
    ]
    if require_site():
        mods.append(
            "create-backend --backend-name site --set base-dn:o=site --type je --set enabled:true --set db-cache-percent:20",
        )
    hostname = guess_host_addr()
    binddn = manager.config.get("ldap_binddn")

    for mod in mods:
        cmd = " ".join([
            "/opt/opendj/bin/dsconfig",
            "--trustAll",
            "--no-prompt",
            f"--hostname {hostname}",
            "--port 4444",
            f"--bindDN '{binddn}'",
            f"--bindPasswordFile {DEFAULT_ADMIN_PW_PATH}",
            mod,
        ])
        _, err, code = exec_cmd(cmd)
        if code:
            logger.warning(err.decode())
            sys.exit(1)


def configure_opendj():
    logger.info("Configuring OpenDJ.")

    host = "localhost:1636"
    user = manager.config.get("ldap_binddn")
    password = decode_text(
        manager.secret.get("encoded_ox_ldap_pw"),
        manager.secret.get("encoded_salt")
    )

    ldap_server = ldap3.Server(host, 1636, use_ssl=True)

    mods = [
        ('ds-cfg-backend-id=userRoot,cn=Backends,cn=config', 'ds-cfg-db-cache-percent', '70', ldap3.MODIFY_REPLACE),
        ('cn=config', 'ds-cfg-single-structural-objectclass-behavior', 'accept', ldap3.MODIFY_REPLACE),
        ('cn=config', 'ds-cfg-reject-unauthenticated-requests', 'true', ldap3.MODIFY_REPLACE),
        ('cn=Default Password Policy,cn=Password Policies,cn=config', 'ds-cfg-allow-pre-encoded-passwords', 'true', ldap3.MODIFY_REPLACE),
        ('cn=Default Password Policy,cn=Password Policies,cn=config', 'ds-cfg-default-password-storage-scheme', 'cn=Salted SHA-512,cn=Password Storage Schemes,cn=config', ldap3.MODIFY_REPLACE),
        ('cn=File-Based Audit Logger,cn=Loggers,cn=config', 'ds-cfg-enabled', 'true', ldap3.MODIFY_REPLACE),
        ('cn=LDAP Connection Handler,cn=Connection Handlers,cn=config', 'ds-cfg-enabled', 'false', ldap3.MODIFY_REPLACE),
        ('cn=JMX Connection Handler,cn=Connection Handlers,cn=config', 'ds-cfg-enabled', 'false', ldap3.MODIFY_REPLACE),
        ('cn=Access Control Handler,cn=config', 'ds-cfg-global-aci', '(targetattr!="userPassword||authPassword||debugsearchindex||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN")(version 3.0; acl "Anonymous read access"; allow (read,search,compare) userdn="ldap:///anyone";)', ldap3.MODIFY_DELETE),
    ]

    if not is_wrends():
        mods.append(
            ("cn=Core Schema,cn=Schema Providers,cn=config", "ds-cfg-allow-zero-length-values-directory-string", "true", ldap3.MODIFY_REPLACE)
        )

    with ldap3.Connection(ldap_server, user, password) as conn:
        for dn, attr, value, mod_type in mods:
            conn.modify(dn, {attr: [mod_type, value]})
            if conn.result["description"] != "success":
                logger.warning(conn.result["message"])

    # Create uniqueness for attrbiutes
    with ldap3.Connection(ldap_server, user, password) as conn:
        attrs = [
            ("mail", "Unique mail address"),
            ("uid", "Unique uid entry"),
        ]

        for attr, cn in attrs:
            conn.add(
                'cn={},cn=Plugins,cn=config'.format(cn),
                attributes={
                    'objectClass': ['top', 'ds-cfg-plugin', 'ds-cfg-unique-attribute-plugin'],
                    'ds-cfg-java-class': ['org.opends.server.plugins.UniqueAttributePlugin'],
                    'ds-cfg-enabled': ['true'],
                    'ds-cfg-plugin-type': [
                        'postoperationadd',
                        'postoperationmodify',
                        'postoperationmodifydn',
                        'postsynchronizationadd',
                        'postsynchronizationmodify',
                        'postsynchronizationmodifydn',
                        'preoperationadd',
                        'preoperationmodify',
                        'preoperationmodifydn',
                    ],
                    'ds-cfg-type': [attr],
                    'cn': [cn],
                    'ds-cfg-base-dn': ['o=gluu']
                }
            )
            if conn.result["description"] != "success":
                logger.warning(conn.result["message"])


def disable_tls13():
    security_file = "/usr/lib/jvm/default-jvm/jre/conf/security/java.security"

    with open(security_file) as f:
        data = javaproperties.loads(f.read())

        if "TLSv1.3" in data["jdk.tls.disabledAlgorithms"]:
            return

    with open(security_file, "w") as f:
        data["jdk.tls.disabledAlgorithms"] = "TLSv1.3, " + data["jdk.tls.disabledAlgorithms"]
        f.write(javaproperties.dumps(data))


if __name__ == "__main__":
    main()
