import json
import logging
import logging.config
import os
import shlex
import shutil
import subprocess
from contextlib import contextmanager

from ldap_peer import guess_host_addr
from settings import LOGGING_CONFIG

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import exec_cmd

GLUU_ADMIN_PORT = os.environ.get("GLUU_ADMIN_PORT", 4444)
GLUU_REPLICATION_PORT = os.environ.get("GLUU_REPLICATION_PORT", 8989)
GLUU_JMX_PORT = os.environ.get("GLUU_JMX_PORT", 1689)
GLUU_CERT_ALT_NAME = os.environ.get("GLUU_CERT_ALT_NAME", "")
GLUU_PERSISTENCE_TYPE = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
GLUU_PERSISTENCE_LDAP_MAPPING = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")
DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

manager = get_manager()

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")


def install_opendj():
    logger.info("Installing OpenDJ.")

    # 1) render opendj-setup.properties
    ctx = {
        "ldap_hostname": guess_host_addr(),
        "ldap_port": manager.config.get("ldap_port"),
        "ldaps_port": manager.config.get("ldaps_port"),
        "ldap_jmx_port": GLUU_JMX_PORT,
        "ldap_admin_port": GLUU_ADMIN_PORT,
        "opendj_ldap_binddn": manager.config.get("ldap_binddn"),
        "ldapPassFn": DEFAULT_ADMIN_PW_PATH,
        "ldap_backend_type": "je",
    }
    with open("/app/templates/opendj-setup.properties") as fr:
        content = fr.read() % ctx

        with open("/opt/opendj/opendj-setup.properties", "wb") as fw:
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
            decode_text(manager.secret.get("encoded_ldapTrustStorePass"), manager.secret.get("encoded_salt"))
        ),
        "--doNotStart",
    ])
    out, err, code = exec_cmd(cmd)
    if code and err:
        logger.warn(err)

    if all([os.environ.get("JAVA_VERSION", "") >= "1.8.0",
            os.path.isfile("/opt/opendj/config/config.ldif")]):
        with open("/opt/opendj/config/java.properties", "a") as f:
            f.write("\nstatus.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true"
                    "\ndsreplication.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true")


def run_dsjavaproperties():
    _, err, code = exec_cmd("/opt/opendj/bin/dsjavaproperties")
    if code and err:
        logger.warn(err)


def configure_opendj():
    logger.info("Configuring OpenDJ.")

    opendj_prop_name = 'global-aci:\'(targetattr!="userPassword||authPassword||debugsearchindex||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN")(version 3.0; acl "Anonymous read access"; allow (read,search,compare) userdn="ldap:///anyone";)\''
    config_mods = [
        'set-backend-prop --backend-name userRoot --set db-cache-percent:70',
        'set-global-configuration-prop --set single-structural-objectclass-behavior:accept',
        'set-password-policy-prop --policy-name "Default Password Policy" --set allow-pre-encoded-passwords:true',
        'set-log-publisher-prop --publisher-name "File-Based Audit Logger" --set enabled:true',
        'create-backend --backend-name metric --set base-dn:o=metric --type je --set enabled:true --set db-cache-percent:11',

        'set-connection-handler-prop --handler-name "LDAP Connection Handler" --set enabled:false',
        'set-connection-handler-prop --handler-name "JMX Connection Handler" --set enabled:false',
        'set-access-control-handler-prop --remove {}'.format(opendj_prop_name),
        'set-global-configuration-prop --set reject-unauthenticated-requests:true',
        'set-password-policy-prop --policy-name "Default Password Policy" --set default-password-storage-scheme:"Salted SHA-512"',
        'set-global-configuration-prop --set reject-unauthenticated-requests:true',
        'create-plugin --plugin-name "Unique mail address" --type unique-attribute --set enabled:true --set base-dn:o=gluu --set type:mail',
        'create-plugin --plugin-name "Unique uid entry" --type unique-attribute --set enabled:true --set base-dn:o=gluu --set type:uid',

        # 'set-connection-handler-prop --handler-name "LDAPS Connection Handler" --set enabled:true --set listen-address:0.0.0.0',
        # 'set-administration-connector-prop --set listen-address:0.0.0.0',
        # 'set-crypto-manager-prop --set ssl-encryption:true',
    ]

    if not is_wrends():
        config_mods.append(
            'set-attribute-syntax-prop --syntax-name "Directory String" --set allow-zero-length-values:true',
        )

    if require_site():
        config_mods.append(
            'create-backend --backend-name site --set base-dn:o=site --type je --set enabled:true --set db-cache-percent:20',
        )

    hostname = guess_host_addr()
    binddn = manager.config.get("ldap_binddn")

    for config in config_mods:
        cmd = " ".join([
            "/opt/opendj/bin/dsconfig",
            "--trustAll",
            "--no-prompt",
            "--hostname {}".format(hostname),
            "--port {}".format(GLUU_ADMIN_PORT),
            "--bindDN '{}'".format(binddn),
            "--bindPasswordFile {}".format(DEFAULT_ADMIN_PW_PATH),
            "{}".format(config)
        ])
        _, err, code = exec_cmd(cmd)
        if code:
            logger.warn(err)


def index_opendj(backend, data):
    logger.info("Creating indexes for {} backend.".format(backend))

    for attr_map in data:
        attr_name = attr_map['attribute']

        for index_type in attr_map["index"]:
            for backend_name in attr_map["backend"]:
                if backend_name != backend:
                    continue

                index_cmd = " ".join([
                    "/opt/opendj/bin/dsconfig",
                    "create-backend-index",
                    "--backend-name {}".format(backend),
                    "--type generic",
                    "--index-name {}".format(attr_name),
                    "--set index-type:{}".format(index_type),
                    "--set index-entry-limit:4000",
                    "--hostName {}".format(guess_host_addr()),
                    "--port {}".format(GLUU_ADMIN_PORT),
                    "--bindDN '{}'".format(manager.config.get("ldap_binddn")),
                    "-j {}".format(DEFAULT_ADMIN_PW_PATH),
                    "--trustAll",
                    "--noPropertiesFile",
                    "--no-prompt",
                ])
                _, err, code = exec_cmd(index_cmd)
                if code:
                    logger.warn(err)


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

    cmd = "/opt/opendj/bin/status -D '{}' -j {} --connectTimeout 10000".format(
        manager.config.get("ldap_binddn"),
        DEFAULT_ADMIN_PW_PATH,
    )
    out, err, code = exec_cmd(cmd)
    running = out.startswith("Unable to connect to the server")

    if not running:
        exec_cmd("/opt/opendj/bin/start-ds")

    try:
        yield
    except Exception:
        raise
    finally:
        exec_cmd("/opt/opendj/bin/stop-ds --quiet")


def run_upgrade():
    buildinfo = "3.0.1"
    if is_wrends():
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
                assert retcode == 0, "Failed to upgrade OpenDJ; reason={}".format(err)

                # backup current buildinfo
                exec_cmd("cp /opt/opendj/config/buildinfo /opt/opendj/config/buildinfo-{}".format(buildinfo))


def require_site():
    if GLUU_PERSISTENCE_TYPE == "ldap":
        return True
    if GLUU_PERSISTENCE_TYPE == "hybrid" and GLUU_PERSISTENCE_LDAP_MAPPING == "site":
        return True
    return False


def main():
    # server = guess_host_addr()

    # the plain-text admin password is not saved in KV storage,
    # but we have the encoded one
    manager.secret.to_file("encoded_ox_ldap_pw", DEFAULT_ADMIN_PW_PATH, decode=True)

    logger.info("Syncing OpenDJ certs.")
    sync_ldap_certs()
    sync_ldap_pkcs12()

    logger.info("Checking certificate's Subject Alt Name (SAN)")
    san = get_certificate_san("/etc/certs/opendj.crt").replace("DNS:", "")

    if GLUU_CERT_ALT_NAME != san:
        logger.info("Re-generating OpenDJ certs with SAN support.")

        render_san_cnf(GLUU_CERT_ALT_NAME)
        regenerate_ldap_certs()

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
    manager.config.set("ldap_init_host", GLUU_CERT_ALT_NAME)
    manager.config.set("ldap_init_port", 1636)

    # do upgrade if required
    run_upgrade()

    # Below we will check if there is a `/opt/opendj/config/config.ldif` or
    # `/opt/opendj/config/schema` directory with files signalling that OpenDJ
    # has already been successfully deployed and will launch as expected.
    if not any([os.path.isfile("/opt/opendj/config/config.ldif"),
                os.path.isdir("/opt/opendj/config/schema")]):
        cleanup_config_dir()
        install_opendj()

        with ds_context():
            if not is_wrends():
                run_dsjavaproperties()
            configure_opendj()

            with open("/app/templates/index.json") as fr:
                data = json.load(fr)
                index_opendj("userRoot", data)
                if require_site():
                    index_opendj("site", data)

    # post-installation cleanup
    for f in [DEFAULT_ADMIN_PW_PATH, "/opt/opendj/opendj-setup.properties"]:
        try:
            os.unlink(f)
        except OSError:
            pass


def render_san_cnf(name):
    ctx = {"alt_name": name}

    with open("/app/templates/ssl/san.cnf") as fr:
        txt = fr.read() % ctx

        with open("/etc/ssl/san.cnf", "w")as fw:
            fw.write(txt)


def regenerate_ldap_certs():
    suffix = "opendj"
    passwd = decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                         manager.secret.get("encoded_salt"))
    country_code = manager.config.get("country_code")
    state = manager.config.get("state")
    city = manager.config.get("city")
    org_name = manager.config.get("orgName")
    domain = manager.config.get("hostname")
    email = manager.config.get("admin_email")

    # create key with password
    _, err, retcode = exec_cmd(
        "openssl genrsa -des3 -out /etc/certs/{}.key.orig "
        "-passout pass:'{}' 2048".format(suffix, passwd))
    assert retcode == 0, "Failed to generate SSL key with password; reason={}".format(err)

    # create .key
    _, err, retcode = exec_cmd(
        "openssl rsa -in /etc/certs/{0}.key.orig "
        "-passin pass:'{1}' -out /etc/certs/{0}.key".format(suffix, passwd))
    assert retcode == 0, "Failed to generate SSL key; reason={}".format(err)

    # create .csr
    _, err, retcode = exec_cmd(
        "openssl req -new -key /etc/certs/{0}.key "
        "-out /etc/certs/{0}.csr "
        "-config /etc/ssl/san.cnf "
        "-subj /C='{1}'/ST='{2}'/L='{3}'/O='{4}'/CN='{5}'/emailAddress='{6}'".format(suffix, country_code, state, city, org_name, domain, email))
    assert retcode == 0, "Failed to generate SSL CSR; reason={}".format(err)

    # create .crt
    _, err, retcode = exec_cmd(
        "openssl x509 -req -days 365 -in /etc/certs/{0}.csr "
        "-extensions v3_req -extfile /etc/ssl/san.cnf "
        "-signkey /etc/certs/{0}.key -out /etc/certs/{0}.crt".format(suffix))
    assert retcode == 0, "Failed to generate SSL cert; reason={}".format(err)

    with open("/etc/certs/{}.pem".format(suffix), "w") as fw:
        with open("/etc/certs/{}.crt".format(suffix)) as fr:
            ldap_ssl_cert = fr.read()

        with open("/etc/certs/{}.key".format(suffix)) as fr:
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
    assert retcode == 0, "Failed to generate PKCS12 file; reason={}".format(err)


def get_certificate_san(certpath):
    openssl_proc = subprocess.Popen(
        shlex.split("openssl x509 -text -noout -in {}".format(certpath)),
        stdout=subprocess.PIPE,
    )
    grep_proc = subprocess.Popen(
        shlex.split("grep DNS"),
        stdout=subprocess.PIPE,
        stdin=openssl_proc.stdout,
    )
    san = grep_proc.communicate()[0]
    return san.strip()


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
        logger.warn(
            "Found {0} in '/opt/opendj/config/' volume mount. "
            "/opt/opendj/config should be empty for a successful "
            "installation.".format(path)
        )

        if obj != "lost+found":
            logger.warn(
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
            logger.warn(exc)


def is_wrends():
    return os.path.isfile("/opt/opendj/lib/wrends.jar")


if __name__ == "__main__":
    main()
