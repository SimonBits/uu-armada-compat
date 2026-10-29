# SPDX-License-Identifier: GPL-2.0-only
"""Read-only kernel selection. File/dependency/ABI validation remains in LinuxHost."""
import gzip
import hashlib
import os
from pathlib import Path

def running_identity():
    from probes import note_ids
    from core import Failure
    try:
        u=os.uname()
        return {'machine':u.machine,'release':u.release,'version':u.version,
                'build_ids':note_ids(Path('/sys/kernel/notes').read_bytes()),
                'config_sha256':hashlib.sha256(gzip.decompress(Path('/proc/config.gz').read_bytes())).hexdigest()}
    except Exception as error:
        raise Failure('KERNEL_IDENTITY_OR_POLICY') from error

def matches(profile,identity):
    return (identity.get('machine')=='aarch64' and identity.get('release')==profile['release']
            and identity.get('version')==profile['uname_version']
            and identity.get('build_ids')==[profile['kernel_build_id']]
            and identity.get('config_sha256')==profile['config_sha256'])
