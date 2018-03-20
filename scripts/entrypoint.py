import base64
import fcntl
import glob
import json
import logging
import os
import shlex
import socket
import struct
import subprocess

from consulate import Consul
from M2Crypto.EVP import Cipher

GLUU_KV_HOST = os.environ.get('GLUU_KV_HOST', 'localhost')
GLUU_KV_PORT = os.environ.get('GLUU_KV_PORT', 8500)
GLUU_CACHE_TYPE = os.environ.get("GLUU_CACHE_TYPE", 'IN_MEMORY')
GLUU_REDIS_URL = os.environ.get('GLUU_REDIS_URL', 'localhost:6379')
GLUU_LDAP_INIT = os.environ.get("GLUU_LDAP_INIT", False)
GLUU_LDAP_INIT_HOST = os.environ.get('GLUU_LDAP_INIT_HOST', 'localhost')
GLUU_LDAP_INIT_PORT = os.environ.get("GLUU_LDAP_INIT_PORT", 1636)

GLUU_LDAP_PORT = os.environ.get("GLUU_LDAP_PORT", 1389)
GLUU_LDAPS_PORT = os.environ.get("GLUU_LDAPS_PORT", 1636)
GLUU_ADMIN_PORT = os.environ.get("GLUU_ADMIN_PORT", 4444)
GLUU_REPLICATION_PORT = os.environ.get("GLUU_REPLICATION_PORT", 8989)
GLUU_JMX_PORT = os.environ.get("GLUU_JMX_PORT", 1689)

DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

consul = Consul(host=GLUU_KV_HOST, port=GLUU_KV_PORT)

logger = logging.getLogger("entrypoint")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


def get_ip_addr(ifname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = socket.inet_ntoa(fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
    return addr


def guess_ip_addr():
    addr = ""

    # priorities
    for ifname in ("eth1", "eth0", "wlan0"):
        try:
            addr = get_ip_addr(ifname)
        except IOError:
            continue
        else:
            break
    return addr


def encrypt_text(text, key):
    # Porting from pyDes-based encryption (see http://git.io/htxa)
    # to use M2Crypto instead (see https://gist.github.com/mrluanma/917014)
    cipher = Cipher(alg="des_ede3_ecb",
                    key=b"{}".format(key),
                    op=1,
                    iv="\0" * 16)
    encrypted_text = cipher.update(b"{}".format(text))
    encrypted_text += cipher.final()
    return base64.b64encode(encrypted_text)


def decrypt_text(encrypted_text, key):
    # Porting from pyDes-based encryption (see http://git.io/htpk)
    # to use M2Crypto instead (see https://gist.github.com/mrluanma/917014)
    cipher = Cipher(alg="des_ede3_ecb",
                    key=b"{}".format(key),
                    op=0,
                    iv="\0" * 16)
    decrypted_text = cipher.update(base64.b64decode(
        b"{}".format(encrypted_text)
    ))
    decrypted_text += cipher.final()
    return decrypted_text


def exec_cmd(cmd):
    """Executes shell command.

    :param cmd: String of shell command.
    :returns: A tuple consists of stdout, stderr, and return code
              returned from shell command execution.
    """
    args = shlex.split(cmd)
    popen = subprocess.Popen(args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    retcode = popen.returncode
    return stdout, stderr, retcode


def install_opendj():
    logger.info("Installing OpenDJ.")

    # 1) render opendj-setup.properties
    ctx = {
        "ldap_hostname": guess_ip_addr(),
        "ldap_port": consul.kv.get("ldap_port"),
        "ldaps_port": consul.kv.get("ldaps_port"),
        "ldap_jmx_port": GLUU_JMX_PORT,
        "ldap_admin_port": GLUU_ADMIN_PORT,
        "opendj_ldap_binddn": consul.kv.get("ldap_binddn"),
        "ldapPassFn": DEFAULT_ADMIN_PW_PATH,
        "ldap_backend_type": "je",
    }
    with open("/opt/templates/opendj-setup.properties") as fr:
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
            decrypt_text(consul.kv.get("encoded_ldapTrustStorePass"), consul.kv.get("encoded_salt"))
        ),
    ])
    _, err, code = exec_cmd(cmd)
    if code:
        logger.warn(err)

    # 3) run dsjavaproperties
    exec_cmd("/opt/opendj/bin/dsjavaproperties")
    _, err, code = exec_cmd(cmd)
    if code != 3:
        logger.warn(err)


def configure_opendj():
    logger.info("Configuring OpenDJ.")

    opendj_prop_name = 'global-aci:\'(targetattr!="userPassword||authPassword||debugsearchindex||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN")(version 3.0; acl "Anonymous read access"; allow (read,search,compare) userdn="ldap:///anyone";)\''
    config_mods = [
        'set-global-configuration-prop --set single-structural-objectclass-behavior:accept',
        'set-attribute-syntax-prop --syntax-name "Directory String" --set allow-zero-length-values:true',
        'set-password-policy-prop --policy-name "Default Password Policy" --set allow-pre-encoded-passwords:true',
        'set-log-publisher-prop --publisher-name "File-Based Audit Logger" --set enabled:true',
        'create-backend --backend-name site --set base-dn:o=site --type je --set enabled:true',
        'set-connection-handler-prop --handler-name "LDAP Connection Handler" --set enabled:false',
        'set-access-control-handler-prop --remove {}'.format(opendj_prop_name),
        'set-global-configuration-prop --set reject-unauthenticated-requests:true',
        'set-password-policy-prop --policy-name "Default Password Policy" --set default-password-storage-scheme:"Salted SHA-512"',
        'set-crypto-manager-prop --set ssl-encryption:true',
    ]
    hostname = guess_ip_addr()
    binddn = consul.kv.get("ldap_binddn")

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


def render_ldif():
    ctx = {
        # o_site.ldif
        # has no variables

        # appliance.ldif
        'cache_provider_type': GLUU_CACHE_TYPE,
        'redis_url': GLUU_REDIS_URL,
        # oxpassport-config.ldif
        'inumAppliance': consul.kv.get('inumAppliance'),
        'ldap_hostname': consul.kv.get('ldap_init_host'),
        # TODO: currently using std ldaps port 1636 as ldap port.
        # after basic testing we need to do it right, and remove this hack.
        # to do this properly we need to update all templates.
        'ldaps_port': consul.kv.get('ldap_init_port'),
        'ldap_binddn': consul.kv.get('ldap_binddn'),
        'encoded_ox_ldap_pw': consul.kv.get('encoded_ox_ldap_pw'),
        'jetty_base': consul.kv.get('jetty_base'),

        # asimba.ldif
        # attributes.ldif
        # groups.ldif
        # oxidp.ldif
        # scopes.ldif
        'inumOrg': r"{}".format(consul.kv.get('inumOrg')),  # raw string

        # base.ldif
        'orgName': consul.kv.get('orgName'),

        # clients.ldif
        'oxauth_client_id': consul.kv.get('oxauth_client_id'),
        'oxauthClient_encoded_pw': consul.kv.get('oxauthClient_encoded_pw'),
        'hostname': consul.kv.get('hostname'),

        # configuration.ldif
        'oxauth_config_base64': consul.kv.get('oxauth_config_base64'),
        'oxauth_static_conf_base64': consul.kv.get('oxauth_static_conf_base64'),
        'oxauth_openid_key_base64': consul.kv.get('oxauth_openid_key_base64'),
        'oxauth_error_base64': consul.kv.get('oxauth_error_base64'),
        'oxtrust_config_base64': consul.kv.get('oxtrust_config_base64'),
        'oxtrust_cache_refresh_base64': consul.kv.get('oxtrust_cache_refresh_base64'),
        'oxtrust_import_person_base64': consul.kv.get('oxtrust_import_person_base64'),
        'oxidp_config_base64': consul.kv.get('oxidp_config_base64'),
        # 'oxcas_config_base64': consul.kv.get('oxcas_config_base64'),
        'oxasimba_config_base64': consul.kv.get('oxasimba_config_base64'),

        # passport.ldif
        'passport_rs_client_id': consul.kv.get('passport_rs_client_id'),
        'passport_rs_client_base64_jwks': consul.kv.get('passport_rs_client_base64_jwks'),
        'passport_rp_client_id': consul.kv.get('passport_rp_client_id'),
        'passport_rp_client_base64_jwks': consul.kv.get('passport_rp_client_base64_jwks'),

        # people.ldif
        "encoded_ldap_pw": consul.kv.get('encoded_ldap_pw'),

        # scim.ldif
        'scim_rs_client_id': consul.kv.get('scim_rs_client_id'),
        'scim_rs_client_base64_jwks': consul.kv.get('scim_rs_client_base64_jwks'),
        'scim_rp_client_id': consul.kv.get('scim_rp_client_id'),
        'scim_rp_client_base64_jwks': consul.kv.get('scim_rp_client_base64_jwks'),

        # scripts.ldif
        "person_authentication_usercertexternalauthenticator": consul.kv.get("person_authentication_usercertexternalauthenticator"),
        "person_authentication_passportexternalauthenticator": consul.kv.get("person_authentication_passportexternalauthenticator"),
        "dynamic_scope_dynamic_permission": consul.kv.get("dynamic_scope_dynamic_permission"),
        "id_generator_samplescript": consul.kv.get("id_generator_samplescript"),
        "dynamic_scope_org_name": consul.kv.get("dynamic_scope_org_name"),
        "dynamic_scope_work_phone": consul.kv.get("dynamic_scope_work_phone"),
        "cache_refresh_samplescript": consul.kv.get("cache_refresh_samplescript"),
        "person_authentication_yubicloudexternalauthenticator": consul.kv.get("person_authentication_yubicloudexternalauthenticator"),
        "uma_rpt_policy_uma_rpt_policy": consul.kv.get("uma_rpt_policy_uma_rpt_policy"),
        "uma_claims_gathering_uma_claims_gathering": consul.kv.get("uma_claims_gathering_uma_claims_gathering"),
        "person_authentication_basiclockaccountexternalauthenticator": consul.kv.get("person_authentication_basiclockaccountexternalauthenticator"),
        "person_authentication_uafexternalauthenticator": consul.kv.get("person_authentication_uafexternalauthenticator"),
        "person_authentication_otpexternalauthenticator": consul.kv.get("person_authentication_otpexternalauthenticator"),
        "person_authentication_duoexternalauthenticator": consul.kv.get("person_authentication_duoexternalauthenticator"),
        "update_user_samplescript": consul.kv.get("update_user_samplescript"),
        "user_registration_samplescript": consul.kv.get("user_registration_samplescript"),
        "user_registration_confirmregistrationsamplescript": consul.kv.get("user_registration_confirmregistrationsamplescript"),
        "person_authentication_googleplusexternalauthenticator": consul.kv.get("person_authentication_googleplusexternalauthenticator"),
        "person_authentication_u2fexternalauthenticator": consul.kv.get("person_authentication_u2fexternalauthenticator"),
        "person_authentication_supergluuexternalauthenticator": consul.kv.get("person_authentication_supergluuexternalauthenticator"),
        "person_authentication_basicexternalauthenticator": consul.kv.get("person_authentication_basicexternalauthenticator"),
        "scim_samplescript": consul.kv.get("scim_samplescript"),
        "person_authentication_samlexternalauthenticator": consul.kv.get("person_authentication_samlexternalauthenticator"),
        "client_registration_samplescript": consul.kv.get("client_registration_samplescript"),
        "person_authentication_twilio2fa": consul.kv.get("person_authentication_twilio2fa"),
        "application_session_samplescript": consul.kv.get("application_session_samplescript"),
        "uma_rpt_policy_umaclientauthzrptpolicy": consul.kv.get("uma_rpt_policy_umaclientauthzrptpolicy"),
        "person_authentication_samlpassportauthenticator": consul.kv.get("person_authentication_samlpassportauthenticator"),
        "consent_gathering_consentgatheringsample": consul.kv.get("consent_gathering_consentgatheringsample"),

        # scripts_cred_manager
        "person_authentication_credmanager": consul.kv.get("person_authentication_credmanager"),
        "client_registration_credmanager": consul.kv.get("client_registration_credmanager"),
    }

    ldif_template_base = '/opt/templates/ldif'
    pattern = '/*.ldif'
    for file_path in glob.glob(ldif_template_base + pattern):
        with open(file_path, 'r') as fp:
            template = fp.read()

        # render
        content = template % ctx

        # write to tmpdir
        with open("/tmp/{}".format(os.path.basename(file_path)), 'w') as fp:
            fp.write(content)


def import_ldif():
    logger.info("Adding data into LDAP.")

    ldif_files = map(lambda x: os.path.join("/tmp", x), [
        'base.ldif',
        'appliance.ldif',
        'attributes.ldif',
        'scopes.ldif',
        'clients.ldif',
        'people.ldif',
        'groups.ldif',
        'o_site.ldif',
        'scripts.ldif',
        'scripts_cred_manager.ldif',
        'configuration.ldif',
        'scim.ldif',
        'asimba.ldif',
        'passport.ldif',
        'oxpassport-config.ldif',
        'oxidp.ldif',
    ])

    for ldif_file_fn in ldif_files:
        cmd = " ".join([
            "/opt/opendj/bin/ldapmodify",
            "--hostname {}".format(guess_ip_addr()),
            "--port {}".format(GLUU_ADMIN_PORT),
            "--bindDN '{}'".format(consul.kv.get("ldap_binddn")),
            "-j {}".format(DEFAULT_ADMIN_PW_PATH),
            "--filename {}".format(ldif_file_fn),
            "--trustAll",
            "--useSSL",
            "--defaultAdd",
            "--continueOnError",
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
                    "--hostName {}".format(guess_ip_addr()),
                    "--port {}".format(GLUU_ADMIN_PORT),
                    "--bindDN '{}'".format(consul.kv.get("ldap_binddn")),
                    "-j {}".format(DEFAULT_ADMIN_PW_PATH),
                    "--trustAll",
                    "--noPropertiesFile",
                    "--no-prompt",
                ])
                _, err, code = exec_cmd(index_cmd)
                if code:
                    logger.warn(err)


def as_boolean(val, default=False):
    truthy = set(('t', 'T', 'true', 'True', 'TRUE', '1', 1, True))
    falsy = set(('f', 'F', 'false', 'False', 'FALSE', '0', 0, False))

    if val in truthy:
        return True
    if val in falsy:
        return False
    return default


def register_server(server):
    consul.kv.set("ldap_servers/{}:{}".format(server["host"], server["ldaps_port"]), server)


def replicate_from(peer, server):
    passwd = decrypt_text(consul.kv.get("encoded_ox_ldap_pw"),
                          consul.kv.get("encoded_salt"))

    for base_dn in ["o=gluu", "o=site"]:
        logger.info("Enabling OpenDJ replication of {} between {}:{} and {}:{}.".format(
            base_dn, peer["host"], peer["ldaps_port"], server["host"], server["ldaps_port"],
        ))

        enable_cmd = " ".join([
            "/opt/opendj/bin/dsreplication",
            "enable",
            "--host1 {}".format(peer["host"]),
            "--port1 {}".format(peer["admin_port"]),
            "--bindDN1 '{}'".format(consul.kv.get("ldap_binddn")),
            "--bindPassword1 {}".format(passwd),
            "--replicationPort1 {}".format(peer["replication_port"]),
            "--secureReplication1",
            "--host2 {}".format(server["host"]),
            "--port2 {}".format(server["admin_port"]),
            "--bindDN2 '{}'".format(consul.kv.get("ldap_binddn")),
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
            base_dn, peer["host"], peer["ldaps_port"], server["host"], server["ldaps_port"],
        ))

        init_cmd = " ".join([
            "/opt/opendj/bin/dsreplication",
            "initialize",
            "--baseDN '{}'".format(base_dn),
            "--adminUID admin",
            "--adminPassword {}".format(passwd),
            "--hostSource {}".format(peer["host"]),
            "--portSource {}".format(peer["admin_port"]),
            "--hostDestination {}".format(server["host"]),
            "--portDestination {}".format(server["admin_port"]),
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

    passwd = decrypt_text(consul.kv.get("encoded_ox_ldap_pw"),
                          consul.kv.get("encoded_salt"))

    cmd = " ".join([
        "/opt/opendj/bin/ldapsearch",
        "--hostname {}".format(host),
        "--port {}".format(port),
        "--baseDN ''",
        "--bindDN '{}'".format(consul.kv.get("ldap_binddn")),
        "--bindPassword {}".format(passwd),
        "-Z",
        "-X",
        "--searchScope base",
        "'(objectclass=*)' 1.1",
    ])
    _, _, code = exec_cmd(cmd)
    return code == 0


def sync_ldap_pkcs12():
    logger.info("Syncing OpenDJ cert.")
    pkcs = decrypt_text(consul.kv.get("ldap_pkcs12_base64"),
                        consul.kv.get("encoded_salt"))

    with open(consul.kv.get("ldapTrustStoreFn"), "wb") as fw:
        fw.write(pkcs)


def reindent(text, num_spaces=1):
    text = [(num_spaces * " ") + line.lstrip() for line in text.splitlines()]
    text = "\n".join(text)
    return text


def generate_base64_contents(text, num_spaces=1):
    text = text.encode("base64").strip()
    if num_spaces > 0:
        text = reindent(text, num_spaces)
    return text


def oxtrust_config():
    # keeping redundent data in context of ldif ctx_data dict for now.
    # so that we can easily remove it from here
    ctx = {
        'inumOrg': r"{}".format(consul.kv.get('inumOrg')),  # raw string
        'admin_email': consul.kv.get('admin_email'),
        'inumAppliance': consul.kv.get('inumAppliance'),
        'hostname': consul.kv.get('hostname'),
        'shibJksFn': consul.kv.get('shibJksFn'),
        'shibJksPass': consul.kv.get('shibJksPass'),
        'jetty_base': consul.kv.get('jetty_base'),
        'oxTrustConfigGeneration': consul.kv.get('oxTrustConfigGeneration'),
        'encoded_shib_jks_pw': consul.kv.get('encoded_shib_jks_pw'),
        'oxauth_client_id': consul.kv.get('oxauth_client_id'),
        'oxauthClient_encoded_pw': consul.kv.get('oxauthClient_encoded_pw'),
        'scim_rs_client_id': consul.kv.get('scim_rs_client_id'),
        'scim_rs_client_jks_fn': consul.kv.get('scim_rs_client_jks_fn'),
        'scim_rs_client_jks_pass_encoded': consul.kv.get('scim_rs_client_jks_pass_encoded'),
        'passport_rs_client_id': consul.kv.get('passport_rs_client_id'),
        'passport_rs_client_jks_fn': consul.kv.get('passport_rs_client_jks_fn'),
        'passport_rs_client_jks_pass_encoded': consul.kv.get('passport_rs_client_jks_pass_encoded'),
        'shibboleth_version': consul.kv.get('shibboleth_version'),
        'idp3Folder': consul.kv.get('idp3Folder'),
        'orgName': consul.kv.get('orgName'),
        'ldap_site_binddn': consul.kv.get('ldap_site_binddn'),
        'encoded_ox_ldap_pw': consul.kv.get('encoded_ox_ldap_pw'),
        'ldap_hostname': consul.kv.get('ldap_init_host'),
        'ldaps_port': consul.kv.get('ldap_init_port'),
    }

    oxtrust_template_base = '/opt/templates/oxtrust'

    key_and_jsonfile_map = {
        'oxtrust_cache_refresh_base64': 'oxtrust-cache-refresh.json',
        'oxtrust_config_base64': 'oxtrust-config.json',
        'oxtrust_import_person_base64': 'oxtrust-import-person.json'
    }

    for key, json_file in key_and_jsonfile_map.iteritems():
        json_file_path = os.path.join(oxtrust_template_base, json_file)
        with open(json_file_path, 'r') as fp:
            consul.kv.set(key, generate_base64_contents(fp.read() % ctx))


def sync_ldap_certs():
    """Gets opendj.crt, opendj.key, and opendj.pem
    """
    ssl_cert = decrypt_text(consul.kv.get("ldap_ssl_cert"), consul.kv.get("encoded_salt"))
    with open("/etc/certs/opendj.crt", "w") as fw:
        fw.write(ssl_cert)
    ssl_key = decrypt_text(consul.kv.get("ldap_ssl_key"), consul.kv.get("encoded_salt"))
    with open("/etc/certs/opendj.key", "w") as fw:
        fw.write(ssl_key)
    ssl_cacert = decrypt_text(consul.kv.get("ldap_ssl_cacert"), consul.kv.get("encoded_salt"))
    with open("/etc/certs/opendj.pem", "w") as fw:
        fw.write(ssl_cacert)


def main():
    server = {
        "host": guess_ip_addr(),
        "ldap_port": GLUU_LDAP_PORT,
        "ldaps_port": GLUU_LDAPS_PORT,
        "admin_port": GLUU_ADMIN_PORT,
        "replication_port": GLUU_REPLICATION_PORT,
    }

    # the plain-text admin password is not saved in KV storage,
    # but we have the encoded one
    with open(DEFAULT_ADMIN_PW_PATH, "wb") as fw:
        admin_pw = decrypt_text(
            consul.kv.get("encoded_ox_ldap_pw"),
            consul.kv.get("encoded_salt"),
        )
        fw.write(admin_pw)

    sync_ldap_certs()
    sync_ldap_pkcs12()

    install_opendj()
    configure_opendj()

    with open("/opt/templates/index.json") as fr:
        data = json.load(fr)
        index_opendj("userRoot", data)
        index_opendj("site", data)

    if as_boolean(GLUU_LDAP_INIT):
        consul.kv.set('ldap_init_host', GLUU_LDAP_INIT_HOST)
        consul.kv.set('ldap_init_port', GLUU_LDAP_INIT_PORT)
        # @TODO: enable oxTrustConfigGeneration
        consul.kv.set("oxTrustConfigGeneration", False)

        oxtrust_config()
        render_ldif()
        import_ldif()
    else:
        peers = {
            k: json.loads(v) for k, v in consul.kv.find("ldap_servers", {}).iteritems()
            if k != "ldap_servers/{}:{}".format(server["host"], server["ldaps_port"])
        }
        for idx, peer in peers.iteritems():
            # if peer is not active, skip and try another one
            if not check_connection(peer["host"], peer["ldaps_port"]):
                continue
            # replicate from active server, no need to replicate from remaining peer
            replicate_from(peer, server)
            break

    # register current server for discovery
    register_server(server)

    try:
        os.unlink(DEFAULT_ADMIN_PW_PATH)
        os.unlink("/opt/opendj/opendj-setup.properties")
    except OSError:
        pass


if __name__ == "__main__":
    main()
