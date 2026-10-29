# SPDX-License-Identifier: GPL-2.0-only
"""Offline package integrity, explicit lifecycle transactions and private diagnostics.
No network downloader, UU control, shell command execution or implicit module removal.
"""
import contextlib
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import uuid

PRODUCT = 'uu-armada-compat'
UNIT = PRODUCT + '.service'
VERSION = '0.1.0'
# Byte-identical unit in the independently preserved RC1, RC2 and RC3 packages.
KNOWN_UNIT_SHA256 = 'e2327ae3f2738747cd1dc0be76182d9240b2b8486f80c063ca6eac0bbdc65fc7'

class Failure(RuntimeError):
    def __init__(self, code, rc=None):
        self.code = code
        self.rc = rc if type(rc) is int else None
        super().__init__(code)

def require(condition, code):
    if not condition:
        raise Failure(code)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def write_json(path, value):
    atomic(path, (json.dumps(value, indent=2, sort_keys=True)+'\n').encode())

def atomic(path, data, mode=0o600):
    require(not path.is_symlink(), 'UNSAFE_PATH')
    fd, name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.replace(name, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(name): os.unlink(name)

def version_key(value):
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?', value)
    require(m is not None, 'VERSION_FORMAT')
    return tuple(map(int, m.groups()[:3])) + ((0,int(m[4])) if m[4] else (1,0))

class Package:
    def __init__(self, path):
        self.path = Path(path).resolve()
        manifest = self.path/'SHA256SUMS'
        require(manifest.is_file() and not manifest.is_symlink(), 'PACKAGE_MANIFEST')
        self.manifest_hash = sha(manifest.read_bytes())
        self.files = {}
        for row in manifest.read_text().splitlines():
            m = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_./-]+)', row)
            require(m is not None, 'PACKAGE_MANIFEST')
            digest, name = m.groups()
            p = Path(name)
            require(not p.is_absolute() and '..' not in p.parts and str(p)==name
                    and name not in self.files and name!='SHA256SUMS', 'PACKAGE_PATH')
            target = self.path/p
            require(all(not q.is_symlink() for q in [target,*list(target.parents)[:len(p.parts)-1]]), 'PACKAGE_SYMLINK')
            require(target.is_file() and target.stat().st_nlink==1, 'PACKAGE_FILE')
            require(sha(target.read_bytes())==digest, 'PACKAGE_INTEGRITY')
            self.files[name] = digest
        actual = {str(p.relative_to(self.path)) for p in self.path.rglob('*') if not p.is_dir()}
        require(actual==set(self.files)|{'SHA256SUMS'}, 'PACKAGE_EXTRA_FILES')
        require(not any(p.is_symlink() for p in self.path.rglob('*')), 'PACKAGE_SYMLINK')
        required={'release.json','profile.json','runtime/core.py','runtime/host.py','runtime/probes.py',
                  'runtime/cli.py','runtime/dnat.py','systemd/'+UNIT,
                  'install.sh','upgrade.sh','uninstall.sh','status.sh'}
        require(required<=set(self.files), 'PACKAGE_INCOMPLETE')
        self.release = json.loads((self.path/'release.json').read_text())
        catalog = json.loads((self.path/'profile.json').read_text())
        require(self.release.get('product')==PRODUCT and self.release.get('schema')==1, 'PACKAGE_PRODUCT')
        self.version = self.release['version']; version_key(self.version)
        self._profile = None
        self.profiles = {}
        self.selected_id = None
        if catalog.get('schema') == 2:
            require('runtime/profiles.py' in self.files,'PACKAGE_INCOMPLETE')
            require(isinstance(catalog.get('profiles'),list) and bool(catalog['profiles']), 'PACKAGE_PROFILES')
            build_ids=set()
            for entry in catalog['profiles']:
                require(isinstance(entry,dict) and set(entry)=={'id','profile','module'}, 'PACKAGE_PROFILES')
                label=entry['id']
                require(isinstance(label,str) and re.fullmatch(r'[0-9]{8}\.[0-9a-f]{7}',label) is not None
                        and label not in self.profiles, 'PACKAGE_PROFILES')
                require(entry['profile']=='kernels/'+label+'/profile.json' and
                        entry['module']=='kernels/'+label+'/xt_nat.ko' and
                        entry['profile'] in self.files and entry['module'] in self.files, 'PACKAGE_PROFILES')
                profile=json.loads((self.path/entry['profile']).read_text())
                require(profile['kernel_build_id'] not in build_ids, 'PACKAGE_PROFILES')
                build_ids.add(profile['kernel_build_id'])
                require(self.files[entry['module']]==profile['module_sha256'], 'MODULE_INTEGRITY')
                self.profiles[label]={'profile':profile,'module':entry['module']}
        else:
            # Read historical single-kernel installations without rewriting them.
            require('modules/xt_nat.ko' in self.files, 'PACKAGE_INCOMPLETE')
            require(self.files['modules/xt_nat.ko']==catalog['module_sha256'], 'MODULE_INTEGRITY')
            self._profile=catalog
        self.key = self.version+'-'+self.manifest_hash[:16]

    @property
    def profile(self):
        if self._profile is None:
            from profiles import running_identity
            self.choose_profile(running_identity())
        return self._profile

    @profile.setter
    def profile(self,value):
        self._profile=value

    def choose_profile(self,identity):
        from profiles import matches
        if not self.profiles:
            require(matches(self._profile,identity),'KERNEL_IDENTITY_OR_POLICY')
            return
        candidates=[label for label,entry in self.profiles.items() if matches(entry['profile'],identity)]
        require(len(candidates)==1,'KERNEL_IDENTITY_OR_POLICY')
        self.selected_id=candidates[0]
        self._profile=self.profiles[self.selected_id]['profile']

    @property
    def module_path(self):
        self.profile  # Never default to a kernel based on directory order or OS label.
        return self.path/(self.profiles[self.selected_id]['module'] if self.profiles else 'modules/xt_nat.ko')

    def audited_replacement(self,old):
        # Only exact frozen predecessors may cross the historical version-label boundary.
        entries=self.release.get('replaces',[])
        return (isinstance(entries,list) and
                {'version':old.version,'manifest_sha256':old.manifest_hash} in entries and
                old.profile['module_sha256']==self.profile['module_sha256'])

class Manager:
    """host is the only privileged-operation boundary; tests use a recording FakeHost."""
    def __init__(self, host, root=Path('/'), owner_uid=0):
        self.host=host; self.root=Path(root); self.owner_uid=owner_uid
        self.store=self.root/'var/lib'/PRODUCT
        self.unit=self.root/'etc/systemd/system'/UNIT
        self.wants=self.unit.parent/'multi-user.target.wants'/UNIT
        self.lock_path=self.root/'run'/ (PRODUCT+'.lock')

    def trusted(self, path, directory=False):
        st=path.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid==self.owner_uid
                and not st.st_mode & 0o022, 'UNSAFE_OWNERSHIP')
        require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink==1,
                'UNSAFE_PATH')

    @contextlib.contextmanager
    def lock(self):
        self.trusted(self.lock_path.parent,True)
        fd=os.open(self.lock_path, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            self.trusted(self.lock_path)
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise Failure('OPERATION_BUSY')
            yield
        finally: os.close(fd)

    def initialize(self):
        for parent in [self.store.parent,self.unit.parent,self.lock_path.parent]:
            self.trusted(parent,True)
        if not self.store.exists():
            require(not self.store.is_symlink(), 'UNSAFE_PATH')
            self.store.mkdir(mode=0o700)
            write_json(self.store/'owner.json',{'product':PRODUCT,'schema':1})
        self.trusted(self.store,True)
        if not (self.store/'owner.json').exists():
            require(not any(self.store.iterdir()),'FOREIGN_STORE')
            write_json(self.store/'owner.json',{'product':PRODUCT,'schema':1})
        self.trusted(self.store/'owner.json')
        require(json.loads((self.store/'owner.json').read_text())=={'product':PRODUCT,'schema':1},'FOREIGN_STORE')
        for name in ['releases','transactions']:
            p=self.store/name
            if not p.exists(): p.mkdir(mode=0o700)
            self.trusted(p,True)

    def state(self):
        if not self.store.exists(): return {'phase':'absent'}
        self.trusted(self.store.parent,True)
        self.trusted(self.store,True)
        self.trusted(self.store/'owner.json')
        require(json.loads((self.store/'owner.json').read_text()).get('product')==PRODUCT,'FOREIGN_STORE')
        p=self.store/'state.json'
        if not p.exists(): return {'phase':'absent'}
        self.trusted(p)
        state=json.loads(p.read_text())
        require(isinstance(state,dict),'STATE_INCONSISTENT')
        return state

    def save(self,state):
        write_json(self.store/'state.json',state)

    def event(self,code,**details):
        # Only constants, booleans and known fingerprints enter this internal log.
        p=self.store/'events.jsonl'
        if p.exists(): self.trusted(p)
        fd=os.open(p,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a') as f:
            f.write(json.dumps({'utc':utc(),'code':code,**details},sort_keys=True)+'\n')
            f.flush(); os.fsync(f.fileno())

    def stage(self,pkg):
        destination=self.store/'releases'/pkg.key
        if destination.exists():
            self.trusted_release(destination)
            require(Package(destination).manifest_hash==pkg.manifest_hash,'STAGE_CONFLICT')
            return destination
        tmp=Path(tempfile.mkdtemp(prefix='.stage-',dir=self.store/'releases'))
        # Interrupted staging is retained as evidence, never executed or implicitly removed.
        for name in [*pkg.files,'SHA256SUMS']:
            dest=tmp/name
            parent=tmp
            for component in dest.parent.relative_to(tmp).parts:
                parent=parent/component; parent.mkdir(exist_ok=True,mode=0o700)
                self.trusted(parent,True)
            atomic(dest,(pkg.path/name).read_bytes(),0o700 if name.endswith('.sh') else 0o600)
        require(Package(tmp).manifest_hash==pkg.manifest_hash,'STAGE_INTEGRITY')
        tmp.rename(destination)
        return destination

    def trusted_release(self,path):
        self.trusted(path,True)
        for item in path.rglob('*'):
            self.trusted(item,item.is_dir())

    def current(self):
        p=self.store/'current'
        if not p.is_symlink():
            require(not p.exists(),'CURRENT_CONFLICT'); return None
        require(p.lstat().st_uid==self.owner_uid,'UNSAFE_OWNERSHIP')
        target=os.readlink(p)
        require(re.fullmatch(r'releases/[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?-[a-f0-9]{16}',target) is not None,
                'CURRENT_TARGET')
        result=Package(self.store/target)
        self.trusted_release(self.store/target)
        require(target=='releases/'+result.key,'CURRENT_IDENTITY')
        return result

    def select(self,pkg):
        target='releases/'+pkg.key
        p=self.store/'current'
        if p.exists() or p.is_symlink(): self.current()
        temp=self.store/('.link-'+uuid.uuid4().hex)
        temp.symlink_to(target); os.replace(temp,p)

    def enable_link(self):
        if not (self.wants.exists() or self.wants.is_symlink()): return False
        self.trusted(self.wants.parent,True)
        require(self.wants.is_symlink() and self.wants.lstat().st_uid==self.owner_uid,
                'FOREIGN_ENABLE_LINK')
        # systemctl may create a relative link. Check its lexical absolute target,
        # then validate the actual unit separately; never follow an arbitrary link.
        target=os.path.abspath(self.wants.parent/os.readlink(self.wants))
        require(target==str(self.unit),'FOREIGN_ENABLE_LINK')
        return True

    def unit_owned(self,state):
        self.trusted(self.unit.parent,True)
        if self.unit.exists() or self.unit.is_symlink():
            self.trusted(self.unit)
            require(stat.S_IMODE(self.unit.stat().st_mode)==0o644 and
                    (self.owner_uid!=0 or self.unit.stat().st_gid==0),'UNIT_FILE_PERMISSIONS')
            digest=sha(self.unit.read_bytes())
            recorded={state.get('unit_sha256'),state.get('unit_previous_sha256')}-{None}
            require(digest in recorded,'UNIT_RECORD_MISMATCH' if recorded else 'FOREIGN_UNIT')
            # A writable state record is not by itself proof of a legitimate unit.
            # Check against a verified release in this installation as well.
            verified=digest==KNOWN_UNIT_SHA256
            # Known historical unit remains verifiable even during a resumable
            # uninstall where release files have already been partially removed.
            if not verified:
                for folder in (self.store/'releases').iterdir() if (self.store/'releases').exists() else []:
                    if folder.name.startswith('.stage-'): continue
                    release=Package(folder); self.trusted_release(folder)
                    require(folder.name==release.key,'RELEASE_OWNERSHIP')
                    if release.files['systemd/'+UNIT]==digest: verified=True
            require(verified,'FOREIGN_UNIT')
        self.enable_link()

    def check_record(self,state,old):
        if old is None:
            require(not state.get('load') and state.get('phase') not in ['installed','upgrading'],
                    'STATE_INCONSISTENT')
            return
        # A crash between the write-ahead version and current symlink switch is
        # allowed only when a matching, private transaction proves the intent.
        if state.get('version')!=old.version:
            require(state.get('phase') in ['installing','upgrading','failed'],'STATE_INCONSISTENT')
            matched=False
            for path in (self.store/'transactions').glob('*.json'):
                self.trusted(path)
                t=json.loads(path.read_text())
                candidate=t.get('candidate','')
                if (t.get('result')=='started' and t.get('old')==old.key and
                        isinstance(candidate,str) and candidate.startswith(str(state.get('version'))+'-')):
                    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?-[a-f0-9]{16}',candidate) is not None,'STATE_INCONSISTENT')
                    self.trusted_release(self.store/'releases'/candidate)
                    release=Package(self.store/'releases'/candidate)
                    require(release.key==candidate,'STATE_INCONSISTENT')
                    matched=True
            require(matched,'STATE_INCONSISTENT')

    def configure(self,pkg,state):
        self.unit_owned(state)
        content=(pkg.path/'systemd'/UNIT).read_bytes()
        same=self.unit.exists() and self.unit.read_bytes()==content
        state['unit_previous_sha256']=sha(self.unit.read_bytes()) if self.unit.exists() else None
        state['unit_sha256']=sha(content)
        if not same: state['unit_reload_pending']=True
        self.save(state)
        if not same: atomic(self.unit,content,0o644)
        if state.get('unit_reload_pending') or self.host.unit_needs_reload():
            self.host.daemon_reload()
        self.host.unit_available(require_loaded=True)
        state.pop('unit_reload_pending',None)
        if not self.wants.parent.exists(): self.wants.parent.mkdir(mode=0o755)
        self.trusted(self.wants.parent,True)
        self.unit_owned(state)
        if not self.enable_link(): self.wants.symlink_to(str(self.unit))
        state.pop('unit_previous_sha256',None)
        state['enabled']=True; self.save(state)

    def disable(self,state):
        self.unit_owned(state)
        if self.enable_link():
            state['unit_reload_pending']=True; self.save(state)
            self.wants.unlink()
        if state.get('unit_reload_pending'):
            self.host.daemon_reload()
            state.pop('unit_reload_pending',None)
        state['enabled']=False; self.save(state)

    def target_ready(self,pkg,state):
        self.unit_owned(state)
        current=self.current()
        if not (current and current.key==pkg.key and self.unit.exists() and
                sha(self.unit.read_bytes())==pkg.files['systemd/'+UNIT] and
                self.enable_link() and state.get('enabled') and not state.get('unit_reload_pending')):
            return False
        if self.host.unit_needs_reload(): return False
        self.host.unit_available(require_loaded=True)
        snapshot=self.host.snapshot(); self.host.health(snapshot)
        own=state.get('load',{})
        if not (snapshot['module']['loaded'] and own.get('ready') is True and
                own.get('boot_id')==snapshot['boot_id'] and own.get('sha256')==pkg.profile['module_sha256']):
            return False
        self.host.module_identity(pkg,snapshot['module'])
        return True

    def ensure_loaded(self,pkg,state):
        self.host.preflight(pkg)
        before=self.host.snapshot()
        self.host.health(before)
        module=before['module']
        if module['loaded']:
            own=state.get('load',{})
            require(own.get('boot_id')==before['boot_id'] and own.get('sha256')==pkg.profile['module_sha256'],
                    'UNOWNED_MODULE')
            self.host.module_identity(pkg,module)
            if own.get('ready'):
                return
            require(not before['tun'],'RECOVERY_TUN_ACTIVE')
            before=own['before']  # Never erase a failed load's original health/network baseline.
        else:
            require(not before['tun'],'TUN_ACTIVE')
            require(self.host.power_allowed(),'POWER_UNSAFE')
            self.host.prepare_dependencies(pkg)
            state['load']={'boot_id':before['boot_id'],'sha256':pkg.profile['module_sha256'],
                           'kernel_build_id':pkg.profile['kernel_build_id'],
                           'ready':False,'before':before,'attempt_utc':utc()}
            self.save(state); self.event('MODULE_LOAD_ATTEMPT')
            self.host.insert(pkg.module_path)
        self.host.module_identity(pkg,self.host.snapshot()['module'])
        self.host.dnat(pkg)
        self.host.observe(before)
        state['load']['ready']=True; self.save(state)
        self.event('MODULE_READY',module_sha256=pkg.profile['module_sha256'])

    def removal_check(self,pkg,state):
        """Read-only gate; safe_remove repeats it immediately before mutation."""
        before=self.host.snapshot()
        if not before['module']['loaded']:
            self.host.health(before)
            require(not before['tun'],'MODULE_OR_TUN_BUSY')
            pending=state.get('load',{}).get('remove_before')
            if pending is not None: self.host.after_remove(pending)
            return before
        own=state.get('load',{})
        require(own.get('boot_id')==before['boot_id'] and own.get('sha256')==pkg.profile['module_sha256'],
                'UNOWNED_MODULE')
        self.host.module_identity(pkg,before['module'])
        self.host.safe_unload(before,own['before'])
        return before

    def safe_remove(self,pkg,state):
        before=self.removal_check(pkg,state)
        if not before['module']['loaded']:
            state.pop('load',None); self.save(state); return
        # Retain the immediate baseline across interruption and post-remove failure.
        state['load']['remove_before']=before; self.save(state)
        self.event('MODULE_UNLOAD_ATTEMPT')
        self.host.remove()
        state['load']['remove_returned']=True; self.save(state)
        self.host.after_remove(before)
        state.pop('load',None); self.save(state); self.event('MODULE_REMOVED')

    def restore_uninstall(self,pkg,original,before,link,state,error):
        """Restore only startup metadata when no module removal is observed.
        Never insert a module, repair network rules, or undo completed cleanup.
        Unknown command completion and successful removal require forward recovery.
        """
        if (getattr(error,'code',None)=='COMMAND_TIMEOUT_STATE_UNKNOWN'
                or state.get('load',{}).get('remove_returned')):
            return False
        current=self.host.snapshot()
        if (current['boot_id']!=before['boot_id'] or
                current['module']['loaded']!=before['module']['loaded']):
            return False
        self.host.health(current)
        if current['module']['loaded']:
            require(pkg is not None,'UNOWNED_MODULE')
            self.host.module_identity(pkg,current['module'])
        self.unit_owned(original)
        self.host.unit_available()
        selected=self.current()
        require((selected.key if selected else None)==(pkg.key if pkg else None),'CURRENT_CONFLICT')
        # Preserve the exact validated original link, including relative targets.
        present=self.enable_link()
        if link is not None:
            if present: require(os.readlink(self.wants)==link,'FOREIGN_ENABLE_LINK')
            else: self.wants.symlink_to(link)
        else:
            require(not present,'FOREIGN_ENABLE_LINK')
        if link is not None or state.get('unit_reload_pending'):
            self.host.daemon_reload()
        self.save(original)
        require(self.enable_link()==(link is not None) and self.state()==original,'ROLLBACK_INCOMPLETE')
        return True

    def install(self,pkg,confirmed=False,upgrade=False):
        require(confirmed,'LOCAL_RECOVERY_REQUIRED')
        self.host.preflight(pkg)
        if self.host.native_provider(): return 'NATIVE_PROVIDER'
        self.host.unit_available()  # Detect global overrides before creating an installation.
        with self.lock():
            self.initialize()
            state=self.state()
            require(state.get('phase') not in ['cleanup_pending','uninstall_pending'],'CLEANUP_PENDING')
            old=self.current()
            self.check_record(state,old)
            resuming=old is not None and state.get('phase') in ['installing','failed','upgrading']
            replacement=old is not None and pkg.audited_replacement(old)
            if resuming and old.version!=pkg.version:
                require(version_key(pkg.version)>version_key(old.version) or replacement,'DOWNGRADE_REFUSED')
                require(old.profile['module_sha256']==pkg.profile['module_sha256'],'RESUME_MODULE_CHANGE')
            if upgrade:
                require(old is not None and (state.get('phase')=='installed' or resuming),'NOT_INSTALLED')
                if old.version==pkg.version and not resuming:
                    require(old.manifest_hash==pkg.manifest_hash or replacement,'SAME_VERSION_DIFFERENT_PACKAGE')
                    if self.target_ready(pkg,state): return 'NO_UPGRADE'
                require(version_key(pkg.version)>=version_key(old.version) or replacement,'DOWNGRADE_REFUSED')
            elif old and (old.version!=pkg.version or (replacement and old.manifest_hash!=pkg.manifest_hash)) and not resuming:
                raise Failure('USE_UPGRADE')
            if old and old.version==pkg.version:
                require(old.manifest_hash==pkg.manifest_hash or replacement,'SAME_VERSION_DIFFERENT_PACKAGE')
            self.unit_owned(state)
            self.host.unit_available()
            if old and old.version==pkg.version and state.get('phase')=='installed':
                if self.target_ready(pkg,state): return 'NO_UPGRADE' if upgrade else 'ALREADY_INSTALLED'
            original=json.loads(json.dumps(state))
            destination=self.stage(pkg); candidate=Package(destination)
            tx=self.store/'transactions'/(utc().replace(':','-')+'-'+uuid.uuid4().hex+'.json')
            write_json(tx,{'utc':utc(),'action':'upgrade' if upgrade else 'install',
                           'old':old.key if old else None,'candidate':candidate.key,'before':original,'result':'started'})
            state.update(phase='upgrading' if upgrade else 'installing',version=candidate.version,
                         recovery_confirmed=True)
            self.save(state); self.event('UPGRADE_BEGIN' if upgrade else 'INSTALL_BEGIN')
            self.event('PREFLIGHT_PASSED',kernel_build_id=candidate.profile['kernel_build_id'],
                       module_sha256=candidate.profile['module_sha256'])
            try:
                if old and old.profile['module_sha256']!=candidate.profile['module_sha256']:
                    self.safe_remove(old,state)
                self.select(candidate)
                self.ensure_loaded(candidate,state)
                self.configure(candidate,state)
                require(self.target_ready(candidate,state),'TARGET_STATE_INCOMPLETE')
                state.update(phase='installed',enabled=True,version=candidate.version)
                self.save(state)
                write_json(tx,{'utc':utc(),'action':'upgrade' if upgrade else 'install',
                               'old':old.key if old else None,'candidate':candidate.key,'result':'complete'})
                self.event('INSTALL_COMPLETE' if not upgrade else 'UPGRADE_COMPLETE')
                return 'UPGRADED' if upgrade else 'RECOVERED' if resuming else 'INSTALLED'
            except Exception as exc:
                # No automatic unload on an uncertain health failure. Upgrade rollback changes
                # code pointers only unless a DIFFERENT module was loaded and is safely idle.
                state['phase']='failed'; self.save(state); self.event('OPERATION_FAILED',error_code=exc.code if isinstance(exc,Failure) else 'INTERNAL_OR_IO_ERROR',
                                                               rc=getattr(exc,'rc',None))
                # No failed first install/retry may leave an enabled startup link.
                # This does not unload a potentially unsafe or referenced module.
                try: self.disable(state)
                except Exception:
                    self.event('ROLLBACK_INCOMPLETE')
                    raise Failure('ROLLBACK_INCOMPLETE')
                if upgrade and old:
                    try:
                        different=old.profile['module_sha256']!=candidate.profile['module_sha256']
                        if different: self.safe_remove(candidate,state)
                        self.host.preflight(old)
                        self.select(old)
                        restored=json.loads(json.dumps(original))
                        if different:
                            restored.pop('load',None); self.ensure_loaded(old,restored)
                        restored['unit_sha256']=state.get('unit_sha256',restored.get('unit_sha256'))
                        self.configure(old,restored); self.save(restored)
                        self.event('ROLLBACK_COMPLETE')
                        write_json(tx,{'utc':utc(),'result':'rolled_back','old':old.key,'candidate':candidate.key})
                    except Exception:
                        failed=self.state(); failed['phase']='failed'; self.save(failed)
                        self.event('ROLLBACK_INCOMPLETE')
                        raise Failure('ROLLBACK_INCOMPLETE')
                raise

    def boot_check(self,pkg):
        if self.host.native_provider(): return 'NATIVE_PROVIDER'
        self.host.preflight(pkg)
        self.host.unit_available(require_loaded=True)
        state=self.state()
        self.unit_owned(state)
        current=self.current(); self.check_record(state,current)
        require(current is not None and current.key==pkg.key and self.unit.exists() and
                sha(self.unit.read_bytes())==pkg.files['systemd/'+UNIT] and self.enable_link(),
                'BOOT_NOT_INSTALLED')
        require(state.get('phase')=='installed' and state.get('enabled') and state.get('recovery_confirmed'),
                'BOOT_NOT_INSTALLED')
        return 'COMPATIBLE'

    def boot(self,pkg):
        with self.lock():
            self.initialize()
            result=self.boot_check(pkg)
            if result=='NATIVE_PROVIDER': return result
            state=self.state()
            self.ensure_loaded(pkg,state)
            self.event('BOOT_READY')
        return 'BOOT_READY'

    def finish_uninstall(self,state):
        # A persisted exact file inventory makes interrupted file removal resumable.
        require(not self.host.snapshot()['module']['loaded'],'MODULE_REAPPEARED')
        self.unit_owned(state)
        plan=state['cleanup']
        receipt=None
        name=state.get('uninstall_transaction')
        if name is not None:
            require(isinstance(name,str) and re.fullmatch(r'[0-9T.+:-]+-[a-f0-9]{32}\.json',name) is not None,
                    'CLEANUP_PATH')
            receipt=self.store/'transactions'/name
            self.trusted(receipt)
            record=json.loads(receipt.read_text())
            require(record.get('action')=='uninstall' and record.get('result') in ['started','recovery_required','complete'],
                    'STATE_INCONSISTENT')
        for key,files in plan.items():
            require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?-[a-f0-9]{16}',key) is not None,'CLEANUP_PATH')
            require(isinstance(files,dict),'CLEANUP_PATH')
            for name,digest in files.items():
                require(isinstance(name,str) and not Path(name).is_absolute() and '..' not in Path(name).parts
                        and str(Path(name))==name and re.fullmatch(r'[A-Za-z0-9_./-]+',name) is not None
                        and isinstance(digest,str) and re.fullmatch(r'[a-f0-9]{64}',digest) is not None,'CLEANUP_PATH')
            folder=self.store/'releases'/key
            if not folder.exists(): continue
            self.trusted(folder,True)
            actual={str(p.relative_to(folder)) for p in folder.rglob('*') if not p.is_dir()}
            require(actual<=set(files),'CLEANUP_UNKNOWN_FILES')
            for name in actual:
                path=folder/name
                require(not Path(name).is_absolute() and '..' not in Path(name).parts,'CLEANUP_PATH')
                self.trusted(path)
                require(sha(path.read_bytes())==files[name],'CLEANUP_MODIFIED_FILE')
            require(not any(p.is_symlink() for p in folder.rglob('*')),'CLEANUP_SYMLINK')
        self.host.reset_own_unit()
        if self.unit.exists(): self.unit.unlink()
        self.host.daemon_reload()
        current=self.store/'current'
        if current.is_symlink():
            require(os.readlink(current) in {'releases/'+k for k in plan},'CURRENT_TARGET')
            current.unlink()
        else: require(not current.exists(),'CURRENT_CONFLICT')
        for key,files in plan.items():
            folder=self.store/'releases'/key
            if not folder.exists(): continue
            for name in files:
                path=folder/name
                if path.exists(): path.unlink()
            for path in sorted(folder.rglob('*'),key=lambda p:len(p.parts),reverse=True):
                if path.is_dir(): path.rmdir()
            folder.rmdir()
        if receipt is not None:
            record.update(result='complete'); write_json(receipt,record)
        state.pop('uninstall_transaction',None)
        state.update(phase='uninstalled',enabled=False); state.pop('cleanup',None); state.pop('load',None); state.pop('unit_previous_sha256',None)
        self.save(state); self.event('UNINSTALL_COMPLETE')
        return 'UNINSTALLED'

    def uninstall(self):
        with self.lock():
            if not self.store.exists():
                require(not self.store.is_symlink() and not self.unit.exists() and not self.unit.is_symlink()
                        and not self.wants.exists() and not self.wants.is_symlink(),'ORPHAN_UNIT')
                return 'ALREADY_UNINSTALLED'
            self.initialize()
            state=self.state()
            if state.get('phase')=='uninstalled' and not (self.store/'current').exists() and not (self.store/'current').is_symlink():
                require(not self.unit.exists() and not self.unit.is_symlink() and not self.enable_link(), 'ORPHAN_UNIT')
                return 'ALREADY_UNINSTALLED'
            if state.get('phase')=='cleanup_pending':
                self.disable(state)
                return self.finish_uninstall(state)
            # All refusal gates precede persisted intent, link removal or file cleanup.
            self.unit_owned(state)
            self.host.unit_available()
            pkg=self.current()
            self.check_record(state,pkg)
            if pkg is not None:
                if self.host.snapshot()['module']['loaded']: self.host.preflight(pkg)
                before=self.removal_check(pkg,state)
            else:
                require(not state.get('load'),'UNINSTALL_RECOVERY_REQUIRED')
                before=self.host.snapshot(); self.host.health(before)
                require(not before['module']['loaded'],'UNOWNED_MODULE')
                require(not before['tun'],'MODULE_OR_TUN_BUSY')
            releases={}
            for path in (self.store/'releases').iterdir():
                if path.name.startswith('.stage-'): continue
                self.trusted(path,True)
                release=Package(path)
                require(path.name==release.key,'RELEASE_OWNERSHIP')
                releases[path.name]={**release.files,'SHA256SUMS':release.manifest_hash}
            original=json.loads(json.dumps(state))
            link=os.readlink(self.wants) if self.enable_link() else None
            tx=self.store/'transactions'/(utc().replace(':','-')+'-'+uuid.uuid4().hex+'.json')
            record={'utc':utc(),'action':'uninstall','before':original,
                    'enable_link':link,'result':'started'}
            write_json(tx,record)
            try:
                state.update(phase='uninstall_pending',uninstall_transaction=tx.name); self.save(state)
                self.disable(state)
                if pkg is not None: self.safe_remove(pkg,state)
            except BaseException as error:
                try:
                    restored=self.restore_uninstall(pkg,original,before,link,state,error)
                    record.update(result='rolled_back' if restored else 'recovery_required',
                                  error_code=error.code if isinstance(error,Failure) else 'INTERNAL_OR_IO_ERROR')
                    write_json(tx,record)
                    self.event('UNINSTALL_ROLLBACK_COMPLETE' if restored else 'UNINSTALL_RECOVERY_REQUIRED')
                except Exception as rollback_error:
                    self.event('ROLLBACK_INCOMPLETE')
                    raise Failure('ROLLBACK_INCOMPLETE') from rollback_error
                raise
            state.update(phase='cleanup_pending',cleanup=releases); self.save(state)
            return self.finish_uninstall(state)

DIAGNOSTIC_ERROR_CODES = frozenset(['UNLOAD_RULES_UNPROVEN', 'POST_UNLOAD_NETWORK_CHANGED', 'UNIT_RELOAD_STATE_UNKNOWN', 'STATE_INCONSISTENT', 'UNIT_RECORD_MISMATCH', 'UNIT_FILE_PERMISSIONS', 'TARGET_STATE_INCOMPLETE', 'BOOT_NOT_INSTALLED', 'CAPABILITIES_REQUIRED', 'CLEANUP_MODIFIED_FILE', 'CLEANUP_PATH', 'CLEANUP_SYMLINK', 'CLEANUP_UNKNOWN_FILES', 'COMMAND_FAILED', 'COMMAND_OUTPUT_LIMIT', 'COMMAND_TIMEOUT_STATE_UNKNOWN', 'CONTROL_VERSION_MISMATCH', 'CURRENT_CONFLICT', 'CURRENT_IDENTITY', 'CURRENT_TARGET', 'DEPENDENCY_ABI', 'DEPENDENCY_INTEGRITY', 'DEPENDENCY_LOAD_FAILED', 'DEPENDENCY_NAME', 'DEPENDENCY_NOT_LIVE', 'DEPENDENCY_RUNTIME_IDENTITY', 'DOWNGRADE_REFUSED', 'FOREIGN_ENABLE_LINK', 'FOREIGN_STORE', 'FOREIGN_UNIT', 'GATHER_FAILED', 'HOST_IDENTITY_CHANGED', 'HOST_TOOL_ARCHITECTURE', 'UNIT_DROPIN_CONFLICT', 'UNIT_NOT_REGISTERED', 'CLEANUP_PENDING', 'RESUME_MODULE_CHANGE', 'INTERACTIVE_CONFIRMATION_REQUIRED', 'CONFIRMATION_DECLINED', 'CONFIRMATION_INVALID', 'UNIT_RUNTIME_CONFLICT', 'INTERNAL_OR_IO_ERROR', 'ISOLATED_DNAT_FAILED', 'ISOLATED_DNAT_INCOMPLETE', 'KERNEL_CONFIG', 'KERNEL_IDENTITY_OR_POLICY', 'KERNEL_OR_NETWORK_UNHEALTHY', 'LOCAL_RECOVERY_REQUIRED', 'MODULE_ABI', 'MODULE_ELF', 'MODULE_INTEGRITY', 'MODULE_OR_TUN_BUSY', 'MODULE_REAPPEARED', 'MODULE_REMOVE_FAILED', 'MODULE_RUNTIME_IDENTITY', 'NATIVE_MODULE_ABI', 'NATIVE_MODULE_IDENTITY', 'NATIVE_MODULE_LOCATION', 'NETWORK_CHANGED', 'NEW_KERNEL_ALERT', 'NEW_KERNEL_TAINT', 'NOT_HOST_NAMESPACE', 'NOT_INSTALLED', 'OPERATION_BUSY', 'ORPHAN_UNIT', 'PACKAGE_PROFILES', 'PACKAGE_EXTRA_FILES', 'PACKAGE_FILE', 'PACKAGE_INCOMPLETE', 'PACKAGE_INTEGRITY', 'PACKAGE_MANIFEST', 'PACKAGE_PATH', 'PACKAGE_PRODUCT', 'PACKAGE_SYMLINK', 'POWER_UNSAFE', 'RECOVERY_TUN_ACTIVE', 'RELEASE_OWNERSHIP', 'REQUIRED_TOOL_UNAVAILABLE', 'ROLLBACK_INCOMPLETE', 'ROOT_REQUIRED', 'SAME_VERSION_DIFFERENT_PACKAGE', 'SERVICE_FAILED', 'SERVICE_REGRESSED', 'SERVICE_STATE_UNKNOWN', 'SNAPSHOT_UNAVAILABLE', 'STAGE_CONFLICT', 'STAGE_INTEGRITY', 'TUN_ACTIVE', 'UNINSTALL_RECOVERY_REQUIRED', 'UNOWNED_MODULE', 'UNSAFE_OWNERSHIP', 'UNSAFE_PATH', 'USE_UPGRADE', 'UU_CORE_NOT_OBSERVED', 'UU_CORE_REGRESSED', 'UU_SERVICE_UNHEALTHY', 'VERSION_FORMAT'])

# Diagnostics are a projection, never a copy of raw logs or the persistent state.
def diagnostic(host,manager,pkg):
    report={'schema':1,'product':PRODUCT,'version':pkg.version,'utc':utc(),'sections':{},'errors':[]}
    def section(name,fn):
        try: report['sections'][name]=fn()
        except Exception as exc:
            report['errors'].append(name.upper()+'_UNAVAILABLE')
            if isinstance(exc,Failure) and exc.code in DIAGNOSTIC_ERROR_CODES:
                report['sections'][name]={'error_code':exc.code}
    section('kernel',lambda:host.diagnostic_identity())
    section('runtime',lambda:host.diagnostic_runtime())
    def selection():
        if host.native_provider(): return {'provider':'native'}
        profile=pkg.profile
        return {'kernel_build_id':profile['kernel_build_id'],
                'module_build_id':profile['module_build_id'],'module_sha256':profile['module_sha256']}
    section('module_selection',selection)
    def installation():
        s=manager.state()
        phases={'absent','installed','installing','upgrading','failed','uninstall_pending','cleanup_pending','uninstalled'}
        result={'phase':s.get('phase') if s.get('phase') in phases else 'unknown',
                'enabled':s.get('enabled') is True,'owned_load_record':isinstance(s.get('load'),dict)}
        current=manager.current() if manager.store.exists() else None
        result['installed_version']=current.version if current else None
        result['installed_manifest_sha256']=current.manifest_hash if current else None
        if manager.store.exists(): manager.unit_owned(s)
        result['unit_integrity']='verified_or_absent'
        events=manager.store/'events.jsonl'
        result['events']=[]
        allowed={'MODULE_LOAD_ATTEMPT','MODULE_READY','MODULE_UNLOAD_ATTEMPT','MODULE_REMOVED',
                 'UPGRADE_BEGIN','INSTALL_BEGIN','INSTALL_COMPLETE','UPGRADE_COMPLETE','OPERATION_FAILED',
                 'UNINSTALL_ROLLBACK_COMPLETE','UNINSTALL_RECOVERY_REQUIRED','ROLLBACK_COMPLETE','ROLLBACK_INCOMPLETE','BOOT_READY','UNINSTALL_COMPLETE','PREFLIGHT_PASSED'}
        if events.exists():
            manager.trusted(events)
            # Bound read; arbitrary injected keys/free text never enter the archive.
            with events.open('rb') as f:
                f.seek(max(0,events.stat().st_size-262144)); data=f.read(262144)
            for line in data.splitlines()[-200:]:
                try:
                    e=json.loads(line)
                    if e.get('code') not in allowed: continue
                    t=e.get('utc','')
                    if not isinstance(t,str) or not re.fullmatch(r'[0-9T:+.Z-]{20,40}',t): continue
                    entry={'utc':t,'code':e['code']}
                    if e.get('error_code') in DIAGNOSTIC_ERROR_CODES: entry['error_code']=e['error_code']
                    if type(e.get('rc')) is int and -128<=e['rc']<=255: entry['rc']=e['rc']
                    result['events'].append(entry)
                except (ValueError,TypeError): pass
        return result
    section('installation',installation)
    return report

def gather(report,output,owner=None):
    # Secure directory traversal and original-user selection are shared with CLI.
    from diagnostic_output import open_directory
    output=Path(output)
    uid,gid=owner if owner is not None else (os.geteuid(),os.getegid())
    directory=open_directory(output.parent,uid)
    try:
        fd=os.open(output.name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=directory)
    finally: os.close(directory)
    try:
        with os.fdopen(fd,'wb') as out:
            os.fchmod(out.fileno(),0o600)
            if os.geteuid()==0: os.fchown(out.fileno(),uid,gid)
            members={'report.json':(json.dumps(report,indent=2,sort_keys=True)+'\n').encode(),
                     'README.txt':b'UU Armada compatibility diagnostics (English, allowlisted).\n'
                     b'No account configuration, environment, network payload, raw firewall rules or UU journal is collected.\n'
                     b'TUN/module use is not proof of functional acceleration.\n'}
            with tarfile.open(fileobj=out,mode='w:gz') as tar:
                for name,data in members.items():
                    info=tarfile.TarInfo(name); info.size=len(data); info.mode=0o600
                    info.uid=info.gid=0; info.uname=info.gname=''
                    tar.addfile(info,io.BytesIO(data))
            out.flush(); os.fsync(out.fileno())
    except Exception:
        raise Failure('GATHER_FAILED')
    return output
