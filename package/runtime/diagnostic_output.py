# SPDX-License-Identifier: GPL-2.0-only
"""Write only an allowlisted archive to a verified original-user output directory."""
import os
from pathlib import Path
import pwd
import stat
import uuid
from core import require,utc,gather


def caller():
    # Never use $HOME, $SUDO_GID or an unchecked user-supplied path as root's home.
    if os.geteuid()==0 and any(k in os.environ for k in ('SUDO_UID','SUDO_USER')):
        value=os.environ.get('SUDO_UID','')
        require(value.isdigit(),'GATHER_CALLER_UNKNOWN')
        try: entry=pwd.getpwuid(int(value))
        except KeyError: require(False,'GATHER_CALLER_UNKNOWN')
        require(entry.pw_name==os.environ.get('SUDO_USER'),'GATHER_CALLER_UNKNOWN')
    else:
        try: entry=pwd.getpwuid(os.getuid())
        except KeyError: require(False,'GATHER_CALLER_UNKNOWN')
    require(Path(entry.pw_dir).is_absolute(),'GATHER_CALLER_UNKNOWN')
    return entry


def open_directory(path,uid):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts,'GATHER_OUTPUT_UNSAFE')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for i,part in enumerate(path.parts[1:]):
            try: new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except OSError: require(False,'GATHER_OUTPUT_UNSAFE')
            os.close(fd);fd=new
            info=os.fstat(fd)
            last=i==len(path.parts)-2
            # Root sticky /tmp is allowed as an ancestor, not as the final target.
            sticky=(not last and info.st_uid==0 and info.st_mode & stat.S_ISVTX)
            require(info.st_uid in [0,uid] and (not info.st_mode & 0o022 or sticky),
                    'GATHER_OUTPUT_UNSAFE')
            if last: require(info.st_uid==uid,'GATHER_OUTPUT_UNSAFE')
            # Do not pollute any package, even when explicit output is nested in it.
            try: os.stat('SHA256SUMS',dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError: pass
            else: require(False,'GATHER_PACKAGE_DIRECTORY')
        require(len(path.parts)>1,'GATHER_OUTPUT_UNSAFE')
        return fd
    except BaseException:
        os.close(fd);raise


def write_report(report,package,store,output_dir=None):
    user=caller()
    if output_dir:
        directory=Path(output_dir)
    else:
        # Fedora Atomic commonly aliases /home to /var/home. Resolve the passwd
        # home, then revalidate the physical directory with no-follow descriptors.
        try: directory=Path(user.pw_dir).resolve(strict=True)
        except OSError: require(False,'GATHER_OUTPUT_UNSAFE')
    if not directory.is_absolute(): directory=Path.cwd()/directory
    # No resolving symlinks here: open_directory rejects them component by component.
    for protected in [Path(package).absolute(),Path(store).absolute()]:
        require(not directory.is_relative_to(protected),'GATHER_PACKAGE_DIRECTORY')
    filename='uu-armada-diagnostic-'+utc().replace(':','-')+'-'+uuid.uuid4().hex[:8]+'.tar.gz'
    return gather(report,directory/filename,(user.pw_uid,user.pw_gid))
