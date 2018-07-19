# OpenDJ

A docker image version of OpenDJ.

## Latest Stable Release

Latest stable release is `gluufederation/opendj:3.1.3_02`. See `CHANGES.md` for archives.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<RELEASE_VERSION>

For example, `gluufederation/opendj:3.1.3_02` consists of:

- glufederation/opendj as `<IMAGE_NAME>`: the actual image name
- 3.1.3 as `GLUU-SERVER-VERSION`: the Gluu Server version as setup reference
- `02` as `<RELEASE_VERSION>`

## Installation

Pull the image:

```
docker pull gluufederation/opendj:3.1.3_02
```

## Environment Variables

- `GLUU_LDAP_INIT`: whether to import initial LDAP entries (possible value are `true` or `false`).
- `GLUU_LDAP_INIT_HOST`: hostname of LDAP for initial configuration (only usable when `GLUU_LDAP_INIT` set to `true`).
- `GLUU_LDAP_INIT_PORT`: port of LDAP for initial configuration (only usable when `GLUU_LDAP_INIT` set to `true`).
- `GLUU_CACHE_TYPE`: supported values are `IN_MEMORY` and `REDIS`, default is `IN_MEMORY`.
- `GLUU_REDIS_URL`: URL of redis service, format is `host:port` (optional).
- `GLUU_REDIS_TYPE`: redis service type, either `STANDALONE` or `CLUSTER` (optional).
- `GLU_LDAP_ADDR_INTERFACE`: interface name where the IP will be guessed and registered as OpenDJ host, e.g. `eth0`.
- `GLU_LDAP_ADVERTISE_ADDR`: the hostname/IP address used as the host of OpenDJ server.
- `GLUU_CONFIG_ADAPTER`: config backend (either `consul` for Consul KV or `kubernetes` for Kubernetes configmap)

The following environment variables are activated only if `GLUU_CONFIG_ADAPTER` is set to `consul`:

- `GLUU_CONSUL_HOST`: hostname or IP of Consul (default to `localhost`)
- `GLUU_CONSUL_PORT`: port of Consul (default to `8500`)
- `GLUU_CONSUL_CONSISTENCY`: Consul consistency mode (choose one of `default`, `consistent`, or `stale`). Default to `stale` mode.

otherwise, if `GLUU_CONFIG_ADAPTER` is set to `kubernetes`:

- `GLUU_KUBERNETES_NAMESPACE`: Kubernetes namespace (default to `default`)
- `GLUU_KUBERNETES_CONFIGMAP`: Kubernetes configmap name (default to `gluu`)

## OpenDJ Peers Discovery

Upon replication, the entrypoint will try to find all peers based on info saved in config backend.
Prior to `3.1.3_02`, the config is called `ldap_servers`.

Here's an example of `ldap_servers` value translated into JSON:

    "ldap_servers": [{"host": "ldap-1", "ldaps_port": 1636}, {"host": "ldap-2", "ldaps_port": 1636}]

Before deploying `gluufederation/opendj:3.1.3_02` container, make sure to migrate the config into:

    "ldap_peers": ["ldap-1", "ldap-2"]

Note: `ldap_peers` value is a JSON string of resolvable addresses of OpenDJ containers.

## Running The Container

Here's an example to run the container as ldap master with initial LDAP entries:

```
docker run -d \
    --name opendj-init \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONSUL_HOST=consul.example.com \
    -e GLUU_LDAP_INIT=true \
    -e GLUU_LDAP_INIT_HOST=ldap.example.com \
    -e GLUU_LDAP_INIT_PORT=1636 \
    -e GLUU_CACHE_TYPE=REDIS \
    -e GLUU_REDIS_URL='redis.example.com:6379' \
    -v /path/to/ldap/db:/opt/opendj/db \
    -v /path/to/ldap/flag:/flag \
    gluufederation/opendj:3.1.3_02
```

Note: to avoid data being re-initialized after container restart, volume mapping of `/flag` directory is encouraged. In the future, the process of LDAP initial data will be taken care by another container.

To add other container(s):

```
docker run -d \
    --name opendj \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONSUL_HOST=consul.example.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_INIT=false \
    -v /path/to/ldap/db:/opt/opendj/db \
    gluufederation/opendj:3.1.3_02
```
