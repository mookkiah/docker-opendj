import argparse
import logging
import os
import sys
import time

from gluulib import get_manager

logger = logging.getLogger("wait_for")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


def wait_for_config(manager, max_wait_time, sleep_duration):
    for i in range(0, max_wait_time, sleep_duration):
        try:
            # we don't care about the result, we only need to test
            # the connection
            manager.config.get("hostname")
            logger.info("Config backend is ready.")
            return
        except Exception as exc:
            logger.warn(
                "Config backend is not ready; reason={}; retrying in {} seconds.".format(
                    exc, sleep_duration))
        time.sleep(sleep_duration)

    logger.error("Config backend is not ready after {} seconds.".format(max_wait_time))
    sys.exit(1)


def wait_for_secret(manager, max_wait_time, sleep_duration):
    for i in range(0, max_wait_time, sleep_duration):
        try:
            # we don't care about the result, we only need to test
            # the connection
            manager.secret.get("ssl_cert")
            logger.info("Secret backend is ready.")
            return
        except Exception as exc:
            logger.warn(
                "Secret backend is not ready; reason={}; retrying in {} seconds.".format(
                    exc, sleep_duration))
        time.sleep(sleep_duration)

    logger.error("Secret backend is not ready after {} seconds.".format(max_wait_time))
    sys.exit(1)


def wait_for(manager, deps=None):
    deps = deps or []

    try:
        max_wait_time = int(os.environ.get("GLUU_WAIT_MAX_TIME", 300))
    except ValueError:
        max_wait_time = 300

    try:
        sleep_duration = int(os.environ.get("GLUU_WAIT_SLEEP_DURATION", 5))
    except ValueError:
        sleep_duration = 5

    if "config" in deps:
        wait_for_config(manager, max_wait_time, sleep_duration)

    if "secret" in deps:
        wait_for_secret(manager, max_wait_time, sleep_duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--deps", help="Comma-separated dependencies to wait for.")
    args = parser.parse_args()

    deps = set(filter(
        None,
        [dep.strip() for dep in args.deps.split(",") if dep]
    ))

    manager = get_manager()
    wait_for(manager, deps)
