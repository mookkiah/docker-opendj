# import base64
import os
import shlex
import subprocess

from consulate import Consul
# from M2Crypto.EVP import Cipher

GLUU_KV_HOST = os.environ.get('GLUU_KV_HOST', 'localhost')
GLUU_KV_PORT = os.environ.get('GLUU_KV_PORT', 8500)
DEFAULT_ADMIN_PW_PATH = "/opt/opendj/.pw"

consul = Consul(host=GLUU_KV_HOST, port=GLUU_KV_PORT)


# def decrypt_text(encrypted_text, key):
#     # Porting from pyDes-based encryption (see http://git.io/htpk)
#     # to use M2Crypto instead (see https://gist.github.com/mrluanma/917014)
#     cipher = Cipher(alg="des_ede3_ecb",
#                     key=b"{}".format(key),
#                     op=0,
#                     iv="\0" * 16)
#     decrypted_text = cipher.update(base64.b64decode(
#         b"{}".format(encrypted_text)
#     ))
#     decrypted_text += cipher.final()
#     return decrypted_text


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
        "ldap_hostname": "localhost",  # consul.kv.get("hostname"),
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
    hostname = "localhost"  # consul.kv.get("hostname")
    binddn = consul.kv.get("ldap_binddn")

    for config in config_mods:
        cmd = "/opt/opendj/bin/dsconfig --trustAll --no-prompt --hostname {} " \
              "--port 4444 --bindDN '{}' --bindPasswordFile {} {}".format(hostname, binddn, DEFAULT_ADMIN_PW_PATH, config)
        exec_cmd(cmd)


def export_opendj_cert():
    pass


def import_ldif():
    pass


def index_opendj():
    pass


def main():
    with open(DEFAULT_ADMIN_PW_PATH, "wb") as fw:
        fw.write(consul.kv.get("encoded_ldap_pw"))

    install_opendj()
    configure_opendj()

    try:
        os.unlink(DEFAULT_ADMIN_PW_PATH)
    except OSError:
        pass


if __name__ == "__main__":
    main()
