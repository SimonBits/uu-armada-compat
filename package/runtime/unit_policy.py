# SPDX-License-Identifier: GPL-2.0-only
"""Narrow, content-aware vendor drop-in policy. Does not rewrite or mask any drop-in."""
import os
from pathlib import Path
import shlex
import stat
from core import require

VENDOR = {
 '/usr/lib/systemd/system/service.d/10-timeout-abort.conf':('TimeoutStopFailureMode','abort'),
 '/usr/lib/systemd/system/service.d/50-keep-warm.conf':('Environment','SYSTEMD_SLEEP_FREEZE_USER_SESSIONS=0'),
}
SEARCH_ROOTS = [
 '/etc/systemd/system.control','/run/systemd/system.control','/run/systemd/transient',
 '/run/systemd/generator.early','/etc/systemd/system','/etc/systemd/system.attached',
 '/run/systemd/system','/run/systemd/system.attached','/run/systemd/generator',
 '/usr/local/lib/systemd/system','/usr/lib/systemd/system','/run/systemd/generator.late',
]
DROPIN_DIRS=['service.d','uu-.service.d','uu-armada-.service.d','uu-armada-compat.service.d']

def validate_content(name,text):
    require(name in VENDOR and len(text)<=16384,'UNIT_DROPIN_CONFLICT')
    section=None; settings=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';')): continue
        if line.startswith('['):
            require(line=='[Service]' and section is None,'UNIT_DROPIN_CONFLICT')
            section='Service'; continue
        require(section=='Service' and '=' in line and '\\' not in line,'UNIT_DROPIN_CONFLICT')
        key,value=line.split('=',1); key=key.strip(); value=value.strip()
        if key=='Environment':
            try: words=shlex.split(value,posix=True)
            except ValueError: words=[]
            require(words==['SYSTEMD_SLEEP_FREEZE_USER_SESSIONS=0'],'UNIT_DROPIN_CONFLICT')
            value=words[0]
        settings.append((key,value))
    require(settings==[VENDOR[name]],'UNIT_DROPIN_CONFLICT')

def validate_file(name,root=Path('/'),owner_uid=0):
    require(name in VENDOR,'UNIT_DROPIN_CONFLICT')
    path=root/name.lstrip('/')
    # No symlink/mutable parent can impersonate a vendor path.
    for p in [path,*list(path.parents)[:len(Path(name).parts)-2]]:
        st=p.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid==owner_uid and not st.st_mode & 0o022,
                'UNIT_DROPIN_CONFLICT')
    require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink==1 and path.stat().st_size<=16384,
            'UNIT_DROPIN_CONFLICT')
    validate_content(name,path.read_text(encoding='utf-8'))

def audit(runtime_paths,root=Path('/'),owner_uid=0):
    # Scan applicable directories even before the new unit has been created.
    # Reject unknown/shadowed overrides conservatively; never delete them.
    seen=set(runtime_paths)
    for prefix in SEARCH_ROOTS:
        for suffix in DROPIN_DIRS:
            folder=root/prefix.lstrip('/')/suffix
            if folder.is_symlink(): require(False,'UNIT_DROPIN_CONFLICT')
            if folder.exists():
                seen.update('/'+str(p.relative_to(root)) for p in folder.glob('*.conf'))
    for name in sorted(seen): validate_file(name,root,owner_uid)
    return sorted(seen)
