#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec /usr/bin/python3 -I -B "$BASE/runtime/cli.py" upgrade "$@"
