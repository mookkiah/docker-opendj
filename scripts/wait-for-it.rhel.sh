#!/bin/sh

set -e

source scl_source enable python27 && python /opt/scripts/wait_for_it_.py
