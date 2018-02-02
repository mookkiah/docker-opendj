import base64
import glob
import json
import os
import shlex
import socket
import subprocess

from consulate import Consul
from M2Crypto.EVP import Cipher

GLUU_KV_HOST = os.environ.get('GLUU_KV_HOST', 'localhost')
GLUU_KV_PORT = os.environ.get('GLUU_KV_PORT', 8500)
GLUU_CACHE_TYPE = os.environ.get("GLUU_CACHE_TYPE", 'IN_MEMORY')
GLUU_REDIS_URL = os.environ.get('GLUU_REDIS_URL', 'localhost:6379')

DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

consul = Consul(host=GLUU_KV_HOST, port=GLUU_KV_PORT)


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
    # render opendj-setup.properties
    ctx = {
        "ldap_hostname": socket.getfqdn(),
        "ldap_port": consul.kv.get("ldap_port"),
        "ldaps_port": consul.kv.get("ldaps_port"),
        "ldap_jmx_port": 1689,
        "ldap_admin_port": 4444,
        "opendj_ldap_binddn": consul.kv.get("ldap_binddn"),
        "ldapPassFn": DEFAULT_ADMIN_PW_PATH,
        "ldap_backend_type": "je",
    }
    with open("/opt/templates/opendj-setup.properties") as fr:
        content = fr.read() % ctx

        with open("/opt/opendj/opendj-setup.properties", "wb") as fw:
            fw.write(content)

    # run installer
    cmd = "/opt/opendj/setup --no-prompt --cli --acceptLicense " \
          "--propertiesFilePath /opt/opendj/opendj-setup.properties"
    exec_cmd(cmd)
    # run dsjavaproperties
    exec_cmd("/opt/opendj/bin/dsjavaproperties")


def configure_opendj():
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
        'set-global-configuration-prop --set reject-unauthenticated-requests:true',
    ]
    hostname = socket.getfqdn()
    binddn = consul.kv.get("ldap_binddn")

    for config in config_mods:
        cmd = "/opt/opendj/bin/dsconfig --trustAll --no-prompt --hostname {} " \
              "--port 4444 --bindDN '{}' --bindPasswordFile {} {}".format(hostname, binddn, DEFAULT_ADMIN_PW_PATH, config)
        exec_cmd(cmd)


def export_opendj_cert():
    pass


def render_ldif():
    ctx = {
        # o_site.ldif
        # has no variables

        # appliance.ldif
        'ldap_use_ssl': consul.kv.get('ldap_use_ssl'),
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
        'oxcas_config_base64': consul.kv.get('oxcas_config_base64'),
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
            "--hostname", socket.getfqdn(),
            '--port', '4444',
            '--bindDN', '"%s"' % consul.kv.get("ldap_binddn"),
            '-j', DEFAULT_ADMIN_PW_PATH,
            '--filename', ldif_file_fn,
            '--trustAll',
            '--useSSL',
            '--defaultAdd',
            '--continueOnError',
        ])
        exec_cmd(cmd)


def index_opendj(backend, data):
    for attr_map in data:
        attr_name = attr_map['attribute']

        for index_type in attr_map["index"]:
            for backend_name in attr_map["backend"]:
                if backend_name != backend:
                    continue

                index_cmd = " ".join([
                    '/opt/opendj/bin/dsconfig',
                    'create-backend-index',
                    '--backend-name', backend,
                    '--type', 'generic',
                    '--index-name', attr_name,
                    '--set', 'index-type:%s' % index_type,
                    '--set', 'index-entry-limit:4000',
                    '--hostName', socket.getfqdn(),
                    '--port', '4444',
                    '--bindDN', '"%s"' % consul.kv.get("ldap_binddn"),
                    '-j', DEFAULT_ADMIN_PW_PATH,
                    '--trustAll', '--noPropertiesFile', '--no-prompt',
                ])
                exec_cmd(index_cmd)


def main():
    # the plain-text admin password is not saved in KV storage,
    # but we have the encoded one
    with open(DEFAULT_ADMIN_PW_PATH, "wb") as fw:
        admin_pw = decrypt_text(
            consul.kv.get("encoded_ox_ldap_pw"),
            consul.kv.get("encoded_salt"),
        )
        fw.write(admin_pw)

    install_opendj()
    configure_opendj()

    # @TODO: export certs
    export_opendj_cert()

    with open("/opt/templates/index.json") as fr:
        data = json.load(fr)
        index_opendj("userRoot", data)
        index_opendj("site", data)

    # @TODO: check whether we need to import data or replicate from other server
    render_ldif()
    import_ldif()

    try:
        os.unlink(DEFAULT_ADMIN_PW_PATH)
    except OSError:
        pass


if __name__ == "__main__":
    main()
