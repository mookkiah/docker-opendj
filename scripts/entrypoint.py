import json
import logging
import logging.config
import os
import shlex
import shutil
import subprocess
from contextlib import contextmanager

from ldap_peer import get_ldap_peers
from ldap_peer import guess_host_addr
from settings import LOGGING_CONFIG

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.utils import safe_render

GLUU_CACHE_TYPE = os.environ.get("GLUU_CACHE_TYPE", 'IN_MEMORY')
GLUU_REDIS_URL = os.environ.get('GLUU_REDIS_URL', 'localhost:6379')
GLUU_REDIS_TYPE = os.environ.get('GLUU_REDIS_TYPE', 'STANDALONE')
GLUU_MEMCACHED_URL = os.environ.get('GLUU_MEMCACHED_URL', 'localhost:11211')

GLUU_LDAP_INIT = os.environ.get("GLUU_LDAP_INIT", False)
GLUU_LDAP_INIT_HOST = os.environ.get('GLUU_LDAP_INIT_HOST', 'localhost')
GLUU_LDAP_INIT_PORT = os.environ.get("GLUU_LDAP_INIT_PORT", 1636)
GLUU_OXTRUST_CONFIG_GENERATION = os.environ.get("GLUU_OXTRUST_CONFIG_GENERATION", True)

GLUU_LDAP_PORT = os.environ.get("GLUU_LDAP_PORT", 1389)
GLUU_LDAPS_PORT = os.environ.get("GLUU_LDAPS_PORT", 1636)
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

    if require_statistic():
        config_mods.append(
            'create-backend --backend-name metric --set base-dn:o=metric --type je --set enabled:true --set db-cache-percent:10',
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


def render_ldif(src, dst, ctx):
    with open(src) as f:
        txt = f.read()

    with open(dst, "w") as f:
        f.write(safe_render(txt, ctx))


def import_ldif():
    ldif_mappings = {
        "default": [
            "base.ldif",
            "attributes.ldif",
            "scopes.ldif",
            "scripts.ldif",
            "configuration.ldif",
            "scim.ldif",
            "oxidp.ldif",
            "oxtrust_api.ldif",
            "passport.ldif",
            "oxpassport-config.ldif",
            "98-radius.ldif",
            "gluu_radius_base.ldif",
            "gluu_radius_server.ldif",
        ],
        "user": [
            "people.ldif",
            "groups.ldif",
        ],
        "site": [
            "o_site.ldif",
        ],
        "statistic": [
            "o_metric.ldif",
        ],
        "authorization": [],
        "token": [],
        "client": [
            "clients.ldif",
            "oxtrust_api_clients.ldif",
            "scim_clients.ldif",
            "gluu_radius_clients.ldif",
        ],
    }

    # hybrid means only a subsets of ldif are needed
    if GLUU_PERSISTENCE_TYPE == "hybrid":
        mapping = GLUU_PERSISTENCE_LDAP_MAPPING
        ldif_mappings = {mapping: ldif_mappings[mapping]}

        # `user` mapping requires `o=gluu` which available in `base.ldif`
        if mapping == "user" and "base.ldif" not in ldif_mappings[mapping]:
            ldif_mappings[mapping].insert(0, "base.ldif")

    ctx = prepare_template_ctx()

    for _, files in ldif_mappings.iteritems():
        for file_ in files:
            src = "/app/templates/ldif/{}".format(file_)
            dst = "/app/tmp/{}".format(file_)
            render_ldif(src, dst, ctx)

            logger.info("Importing {} file".format(file_))

            cmd = [
                "/opt/opendj/bin/ldapmodify",
                "--hostname {}".format(guess_host_addr()),
                "--port {}".format(GLUU_ADMIN_PORT),
                "--bindDN '{}'".format(manager.config.get("ldap_binddn")),
                "-j {}".format(DEFAULT_ADMIN_PW_PATH),
                "--filename {}".format(dst),
                "--trustAll",
                "--useSSL",
                "--continueOnError",
            ]

            if not is_wrends():
                cmd.append("--defaultAdd")

            _, err, code = exec_cmd(" ".join(cmd))
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


def replicate_from(peer, server):
    passwd = decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                         manager.secret.get("encoded_salt"))

    dn_list = ["o=gluu"]

    if require_site():
        dn_list.append("o=site")

    if require_statistic():
        dn_list.append("o=metric")

    for base_dn in dn_list:
        logger.info("Enabling OpenDJ replication of {} between {}:{} and {}:{}.".format(
            base_dn, peer, GLUU_LDAPS_PORT, server, GLUU_LDAPS_PORT,
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
            base_dn, peer, GLUU_LDAPS_PORT, server, GLUU_LDAPS_PORT,
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


def check_connection(host, port):
    logger.info("Checking connection to {}:{}.".format(host, port))

    passwd = decode_text(manager.secret.get("encoded_ox_ldap_pw"),
                         manager.secret.get("encoded_salt"))

    cmd = " ".join([
        "/opt/opendj/bin/ldapsearch",
        "--hostname {}".format(host),
        "--port {}".format(port),
        "--baseDN ''",
        "--bindDN '{}'".format(manager.config.get("ldap_binddn")),
        "--bindPassword {}".format(passwd),
        "-Z",
        "-X",
        "--searchScope base",
        "'(objectclass=*)' 1.1",
    ])
    return exec_cmd(cmd)


def sync_ldap_pkcs12():
    dest = manager.config.get("ldapTrustStoreFn")
    manager.secret.to_file("ldap_pkcs12_base64", dest, decode=True, binary_mode=True)


def oxtrust_config():
    ctx = prepare_template_ctx()
    oxtrust_template_base = '/app/templates/oxtrust'

    key_and_jsonfile_map = {
        'oxtrust_cache_refresh_base64': 'oxtrust-cache-refresh.json',
        'oxtrust_config_base64': 'oxtrust-config.json',
        'oxtrust_import_person_base64': 'oxtrust-import-person.json'
    }

    for key, json_file in key_and_jsonfile_map.iteritems():
        json_file_path = os.path.join(oxtrust_template_base, json_file)
        with open(json_file_path, 'r') as fp:
            if json_file == "oxtrust-import-person.json":
                ctx_manager = manager.config
            else:
                ctx_manager = manager.secret
            ctx_manager.set(key, generate_base64_contents(fp.read() % ctx))


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


def require_statistic():
    if GLUU_PERSISTENCE_TYPE == "ldap":
        return True
    if GLUU_PERSISTENCE_TYPE == "hybrid" and GLUU_PERSISTENCE_LDAP_MAPPING == "statistic":
        return True
    return False


def main():
    server = guess_host_addr()

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

    if as_boolean(GLUU_LDAP_INIT):
        if not os.path.isfile("/flag/ldap_initialized"):
            manager.config.set('ldap_init_host', GLUU_LDAP_INIT_HOST)
            manager.config.set('ldap_init_port', GLUU_LDAP_INIT_PORT)

            oxtrust_config()

            with ds_context():
                import_ldif()

            exec_cmd("mkdir -p /flag")
            exec_cmd("touch /flag/ldap_initialized")
    else:
        with ds_context():
            for peer in get_ldap_peers(manager):
                # skip if peer is current server
                if peer == server:
                    continue
                # if peer is not active, skip and try another one
                out, err, code = check_connection(peer, GLUU_LDAPS_PORT)
                if code != 0:
                    logger.warn("unable to connect to peer; reason={}".format(err))
                    continue
                # replicate from active server, no need to replicate from remaining peer
                replicate_from(peer, server)
                break

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


def prepare_template_ctx():
    passport_oxtrust_config = '''
    "passportUmaClientId":"%(passport_rs_client_id)s",
    "passportUmaClientKeyId":"",
    "passportUmaResourceId":"%(passport_resource_id)s",
    "passportUmaScope":"https://%(hostname)s/oxauth/restv1/uma/scopes/passport_access",
    "passportUmaClientKeyStoreFile":"%(passport_rs_client_jks_fn)s",
    "passportUmaClientKeyStorePassword":"%(passport_rs_client_jks_pass_encoded)s",
''' % {
        "passport_rs_client_id": manager.config.get("passport_rs_client_id"),
        "passport_resource_id": manager.config.get("passport_resource_id"),
        "hostname": manager.config.get("hostname"),
        "passport_rs_client_jks_fn": manager.config.get("passport_rs_client_jks_fn"),
        "passport_rs_client_jks_pass_encoded": manager.secret.get("passport_rs_client_jks_pass_encoded")
    }

    ctx = {
        'cache_provider_type': GLUU_CACHE_TYPE,
        'redis_url': GLUU_REDIS_URL,
        'redis_type': GLUU_REDIS_TYPE,
        'memcached_url': GLUU_MEMCACHED_URL,
        'ldap_hostname': manager.config.get('ldap_init_host', ""),
        'ldaps_port': manager.config.get('ldap_init_port', 1636),
        'ldap_binddn': manager.config.get('ldap_binddn'),
        'encoded_ox_ldap_pw': manager.secret.get('encoded_ox_ldap_pw'),
        'jetty_base': manager.config.get('jetty_base'),
        'orgName': manager.config.get('orgName'),
        'oxauth_client_id': manager.config.get('oxauth_client_id'),
        'oxauthClient_encoded_pw': manager.secret.get('oxauthClient_encoded_pw'),
        'hostname': manager.config.get('hostname'),
        'idp_client_id': manager.config.get('idp_client_id'),
        'idpClient_encoded_pw': manager.secret.get('idpClient_encoded_pw'),
        'oxauth_config_base64': manager.secret.get('oxauth_config_base64'),
        'oxauth_static_conf_base64': manager.config.get('oxauth_static_conf_base64'),
        'oxauth_openid_key_base64': manager.secret.get('oxauth_openid_key_base64'),
        'oxauth_error_base64': manager.config.get('oxauth_error_base64'),
        'oxtrust_config_base64': manager.secret.get('oxtrust_config_base64'),
        'oxtrust_cache_refresh_base64': manager.secret.get('oxtrust_cache_refresh_base64'),
        'oxtrust_import_person_base64': manager.config.get('oxtrust_import_person_base64'),
        'oxidp_config_base64': manager.secret.get('oxidp_config_base64'),

        'passport_central_config_base64': manager.secret.get("passport_central_config_base64"),
        'passport_rs_client_id': manager.config.get('passport_rs_client_id'),
        'passport_rs_client_base64_jwks': manager.secret.get('passport_rs_client_base64_jwks'),
        'passport_rp_client_id': manager.config.get('passport_rp_client_id'),
        'passport_rp_client_base64_jwks': manager.secret.get('passport_rp_client_base64_jwks'),
        "passport_rp_client_jks_fn": manager.config.get("passport_rp_client_jks_fn"),
        "passport_rp_client_jks_pass": manager.secret.get("passport_rp_client_jks_pass"),
        "encoded_ldap_pw": manager.secret.get('encoded_ldap_pw'),
        'scim_rs_client_id': manager.config.get('scim_rs_client_id'),
        'scim_rs_client_base64_jwks': manager.secret.get('scim_rs_client_base64_jwks'),
        'scim_rp_client_id': manager.config.get('scim_rp_client_id'),
        'scim_rp_client_base64_jwks': manager.secret.get('scim_rp_client_base64_jwks'),
        'scim_resource_oxid': manager.config.get('scim_resource_oxid'),
        'passport_rp_ii_client_id': manager.config.get("passport_rp_ii_client_id"),
        'api_rs_client_base64_jwks': manager.secret.get("api_rs_client_base64_jwks"),
        'api_rp_client_base64_jwks': manager.secret.get("api_rp_client_base64_jwks"),

        # scripts.ldif
        "person_authentication_usercertexternalauthenticator": manager.config.get("person_authentication_usercertexternalauthenticator"),
        "person_authentication_passportexternalauthenticator": manager.config.get("person_authentication_passportexternalauthenticator"),
        "dynamic_scope_dynamic_permission": manager.config.get("dynamic_scope_dynamic_permission"),
        "id_generator_samplescript": manager.config.get("id_generator_samplescript"),
        "dynamic_scope_org_name": manager.config.get("dynamic_scope_org_name"),
        "dynamic_scope_work_phone": manager.config.get("dynamic_scope_work_phone"),
        "cache_refresh_samplescript": manager.config.get("cache_refresh_samplescript"),
        "person_authentication_yubicloudexternalauthenticator": manager.config.get("person_authentication_yubicloudexternalauthenticator"),
        "uma_rpt_policy_uma_rpt_policy": manager.config.get("uma_rpt_policy_uma_rpt_policy"),
        "uma_claims_gathering_uma_claims_gathering": manager.config.get("uma_claims_gathering_uma_claims_gathering"),
        "person_authentication_basiclockaccountexternalauthenticator": manager.config.get("person_authentication_basiclockaccountexternalauthenticator"),
        "person_authentication_uafexternalauthenticator": manager.config.get("person_authentication_uafexternalauthenticator"),
        "person_authentication_otpexternalauthenticator": manager.config.get("person_authentication_otpexternalauthenticator"),
        "person_authentication_duoexternalauthenticator": manager.config.get("person_authentication_duoexternalauthenticator"),
        "update_user_samplescript": manager.config.get("update_user_samplescript"),
        "user_registration_samplescript": manager.config.get("user_registration_samplescript"),
        "user_registration_confirmregistrationsamplescript": manager.config.get("user_registration_confirmregistrationsamplescript"),
        "person_authentication_googleplusexternalauthenticator": manager.config.get("person_authentication_googleplusexternalauthenticator"),
        "person_authentication_u2fexternalauthenticator": manager.config.get("person_authentication_u2fexternalauthenticator"),
        "person_authentication_supergluuexternalauthenticator": manager.config.get("person_authentication_supergluuexternalauthenticator"),
        "person_authentication_basicexternalauthenticator": manager.config.get("person_authentication_basicexternalauthenticator"),
        "scim_samplescript": manager.config.get("scim_samplescript"),
        "person_authentication_samlexternalauthenticator": manager.config.get("person_authentication_samlexternalauthenticator"),
        "client_registration_samplescript": manager.config.get("client_registration_samplescript"),
        "person_authentication_twilio2fa": manager.config.get("person_authentication_twilio2fa"),
        "application_session_samplescript": manager.config.get("application_session_samplescript"),
        "uma_rpt_policy_umaclientauthzrptpolicy": manager.config.get("uma_rpt_policy_umaclientauthzrptpolicy"),
        "person_authentication_samlpassportauthenticator": manager.config.get("person_authentication_samlpassportauthenticator"),
        "consent_gathering_consentgatheringsample": manager.config.get("consent_gathering_consentgatheringsample"),
        "person_authentication_thumbsigninexternalauthenticator": manager.config.get("person_authentication_thumbsigninexternalauthenticator"),
        "resource_owner_password_credentials_resource_owner_password_credentials": manager.config.get("resource_owner_password_credentials_resource_owner_password_credentials"),
        "person_authentication_fido2externalauthenticator": manager.config.get("person_authentication_fido2externalauthenticator"),
        "introspection_introspection": manager.config.get("introspection_introspection"),

        'admin_email': manager.config.get('admin_email'),
        'shibJksFn': manager.config.get('shibJksFn'),
        'shibJksPass': manager.secret.get('shibJksPass'),
        'oxTrustConfigGeneration': "true" if as_boolean(GLUU_OXTRUST_CONFIG_GENERATION) else "false",
        'encoded_shib_jks_pw': manager.secret.get('encoded_shib_jks_pw'),
        'scim_rs_client_jks_fn': manager.config.get('scim_rs_client_jks_fn'),
        'scim_rs_client_jks_pass_encoded': manager.secret.get('scim_rs_client_jks_pass_encoded'),
        'passport_rs_client_jks_fn': manager.config.get('passport_rs_client_jks_fn'),
        'passport_rs_client_jks_pass_encoded': manager.secret.get('passport_rs_client_jks_pass_encoded'),
        'shibboleth_version': manager.config.get('shibboleth_version'),
        'idp3Folder': manager.config.get('idp3Folder'),
        'ldap_site_binddn': manager.config.get('ldap_site_binddn'),
        'api_rs_client_jks_fn': manager.config.get("api_rs_client_jks_fn"),
        'api_rs_client_jks_pass_encoded': manager.secret.get("api_rs_client_jks_pass_encoded"),

        "oxtrust_requesting_party_client_id": manager.config.get("oxtrust_requesting_party_client_id"),
        "oxtrust_resource_server_client_id": manager.config.get("oxtrust_resource_server_client_id"),
        "oxtrust_resource_id": manager.config.get("oxtrust_resource_id"),
        "passport_resource_id": manager.config.get("passport_resource_id"),
        "passport_oxtrust_config": passport_oxtrust_config,

        "gluu_radius_client_id": manager.config.get("gluu_radius_client_id"),
        "gluu_ro_encoded_pw": manager.secret.get("gluu_ro_encoded_pw"),
        "super_gluu_ro_session_script": manager.config.get("super_gluu_ro_session_script"),
        "super_gluu_ro_script": manager.config.get("super_gluu_ro_script"),
        "enableRadiusScripts": "false",
        "gluu_ro_client_base64_jwks": manager.secret.get("gluu_ro_client_base64_jwks"),
    }
    return ctx


def is_wrends():
    return os.path.isfile("/opt/opendj/lib/wrends.jar")


if __name__ == "__main__":
    main()
