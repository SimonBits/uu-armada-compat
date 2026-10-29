# SPDX-License-Identifier: GPL-2.0-only
"""Linux operation boundary. All commands are fixed argv; no shell or UU control."""
import gzip
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time

import probes as p
import unit_policy
from core import Failure, require, sha

class LinuxHost:
    def __init__(self,root=Path('/'),owner_uid=0):
        self.policy_root=Path(root); self.policy_uid=owner_uid

    def run(self,args,timeout=10):
        try:
            q=subprocess.run(args,capture_output=True,text=True,timeout=timeout,env=p.ENV)
        except subprocess.TimeoutExpired:
            raise Failure('COMMAND_TIMEOUT_STATE_UNKNOWN')
        except OSError:
            raise Failure('REQUIRED_TOOL_UNAVAILABLE')
        if q.returncode!=0: raise Failure('COMMAND_FAILED',rc=q.returncode)
        require(len(q.stdout)+len(q.stderr)<8*1024*1024,'COMMAND_OUTPUT_LIMIT')
        return q.stdout

    def config(self):
        return gzip.decompress(Path('/proc/config.gz').read_bytes()).decode()

    def native_provider(self):
        config=self.config()
        if 'CONFIG_NETFILTER_XT_NAT=y\n' in config: return True
        if 'CONFIG_NETFILTER_XT_NAT=m\n' in config:
            release=os.uname().release
            location=Path(self.run(['/usr/sbin/modinfo','-n','xt_nat']).strip())
            root=Path('/usr/lib/modules')/release
            require(location.resolve().is_relative_to(root.resolve()) and location.is_file(),'NATIVE_MODULE_LOCATION')
            require(self.run(['/usr/sbin/modinfo','-F','name',str(location)]).strip()=='xt_nat','NATIVE_MODULE_IDENTITY')
            require(self.run(['/usr/sbin/modinfo','-F','vermagic',str(location)]).split()[0]==release,'NATIVE_MODULE_ABI')
            return True
        return False

    def preflight(self,pkg):
        if self.native_provider(): return
        from profiles import running_identity
        pkg.choose_profile(running_identity())
        p.EXPECTED=pkg.profile
        try: p.identity()
        except Exception: raise Failure('KERNEL_IDENTITY_OR_POLICY')
        for tool in ['/usr/bin/iptables','/usr/bin/ip','/usr/bin/nft','/usr/bin/unshare',
                     '/usr/bin/python3','/usr/sbin/insmod','/usr/sbin/rmmod']:
            path=Path(tool)
            require(path.is_file() and os.access(path,os.X_OK),'REQUIRED_TOOL_UNAVAILABLE')
            with path.open('rb') as stream: header=stream.read(64)
            require(header[:6]==b'\x7fELF\x02\x01' and len(header)>=64
                    and struct.unpack_from('<H',header,18)[0]==183,'HOST_TOOL_ARCHITECTURE')
        data=(pkg.module_path).read_bytes()
        require(data[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<HH',data,16)==(1,183),'MODULE_ELF')
        require(sha(data)==pkg.profile['module_sha256'],'MODULE_INTEGRITY')
        info={key:self.run(['/usr/sbin/modinfo','-F',key,str(pkg.module_path)]).strip()
              for key in ['name','vermagic','depends']}
        require(info['name']=='xt_nat' and info['vermagic']==pkg.profile['vermagic']
                and set(info['depends'].split(','))==set(pkg.profile['dependencies']),'MODULE_ABI')
        required=['CONFIG_MODULES=y','CONFIG_MODULE_UNLOAD=y','CONFIG_NETFILTER_XTABLES=m',
                  'CONFIG_NF_CONNTRACK=m','CONFIG_NF_NAT=m']
        config=self.config()
        require(all(x+'\n' in config for x in required),'KERNEL_CONFIG')
        require(p.capabilities() & (1<<16) and p.capabilities() & (1<<21) and p.capabilities() & (1<<12),
                'CAPABILITIES_REQUIRED')
        for name in pkg.profile['dependency_order']:
            path=Path(pkg.profile['dependency_paths'][name])
            require(sha(path.read_bytes())==pkg.profile['files'][str(path)],'DEPENDENCY_INTEGRITY')
            require(self.run(['/usr/sbin/modinfo','-F','vermagic',str(path)]).strip()==pkg.profile['vermagic'],
                    'DEPENDENCY_ABI')
            require(self.run(['/usr/sbin/modinfo','-F','name',str(path)]).strip()==name,'DEPENDENCY_NAME')
            self.dependency_runtime(pkg,name)

    def dependency_runtime(self,pkg,name):
        path=Path('/sys/module')/name
        if not path.exists(): return False
        require((path/'initstate').read_text().strip()=='live','DEPENDENCY_NOT_LIVE')
        require(p.note_ids((path/'notes/.note.gnu.build-id').read_bytes())==[pkg.profile['dependency_build_ids'][name]],
                'DEPENDENCY_RUNTIME_IDENTITY')
        return True

    def prepare_dependencies(self,pkg):
        for name in pkg.profile['dependency_order']:
            if self.dependency_runtime(pkg,name): continue
            path=Path(pkg.profile['dependency_paths'][name])
            require(sha(path.read_bytes())==pkg.profile['files'][str(path)],'DEPENDENCY_INTEGRITY')
            # Exact stock files, dependency order pinned; never execute modprobe install hooks.
            self.insert(path)
            require(self.dependency_runtime(pkg,name),'DEPENDENCY_LOAD_FAILED')

    def snapshot(self):
        try: return p.snapshot()
        except Exception: raise Failure('SNAPSHOT_UNAVAILABLE')

    def health(self,s):
        try: p.environmental_checks(s)
        except Exception: raise Failure('KERNEL_OR_NETWORK_UNHEALTHY')
        for unit in ['uuplugin.service','plugin_loader.service','systemd-resolved.service']:
            fields=dict(line.split('=',1) for line in s['services'][unit].splitlines() if '=' in line)
            require(fields.get('LoadState') in ['not-found','loaded'],'SERVICE_STATE_UNKNOWN')
            if fields.get('LoadState')=='loaded':
                require(fields.get('ActiveState')!='failed','SERVICE_FAILED')
        # No assumption that UU/Steam is already started during early boot.

    def power_allowed(self):
        return p.power_status()['allowed']

    def module_identity(self,pkg,module):
        require(module.get('loaded') and module.get('state')=='live'
                and module.get('build_ids')==[pkg.profile['module_build_id']],'MODULE_RUNTIME_IDENTITY')

    def insert(self,path): self.run(['/usr/sbin/insmod',str(path)],timeout=20)
    def remove(self): self.run(['/usr/sbin/rmmod','xt_nat'],timeout=20)
    def daemon_reload(self): self.run(['/usr/bin/systemctl','daemon-reload'])
    def unit_needs_reload(self):
        values=dict(line.split('=',1) for line in self.run([
            '/usr/bin/systemctl','show','uu-armada-compat.service',
            '-p','LoadState','-p','NeedDaemonReload']).splitlines() if '=' in line)
        if values.get('LoadState')=='not-found': return True
        require(values.get('NeedDaemonReload') in ['yes','no'],'UNIT_RELOAD_STATE_UNKNOWN')
        return values['NeedDaemonReload']=='yes'

    def unit_available(self,require_loaded=False):
        fields=['LoadState','FragmentPath','DropInPaths','Type','Restart','RemainAfterExit',
                'ExecStop','ExecStopPost','TimeoutStartUSec','TimeoutStopUSec','User']
        args=['/usr/bin/systemctl','show','uu-armada-compat.service']
        for field in fields: args+=['-p',field]
        values=dict(line.split('=',1) for line in self.run(args).splitlines() if '=' in line)
        paths=values.get('DropInPaths','').split()
        unit_policy.audit(paths,self.policy_root,self.policy_uid)
        if values.get('LoadState')=='not-found':
            require(not require_loaded,'UNIT_NOT_REGISTERED'); return False
        require(values.get('LoadState')=='loaded' and
                values.get('FragmentPath')=='/etc/systemd/system/uu-armada-compat.service',
                'UNIT_RUNTIME_CONFLICT')
        # On the observed systemd 259, show (even --all) omits empty command
        # arrays. Only these two absent fields may use the typed D-Bus fallback.
        # Do not log the response: a nonempty array can contain command arguments.
        for field in ['ExecStop','ExecStopPost']:
            if field not in values:
                reply=self.run(['/usr/bin/busctl','--system','get-property',
                    'org.freedesktop.systemd1',
                    '/org/freedesktop/systemd1/unit/uu_2darmada_2dcompat_2eservice',
                    'org.freedesktop.systemd1.Service',field],timeout=5)
                require(reply.split()==['a(sasbttttuii)','0'],'UNIT_RUNTIME_CONFLICT')
                values[field]=''
        # Validate merged behavior, not just the vendor filenames.
        expected={'Type':'oneshot','Restart':'no','RemainAfterExit':'yes','ExecStop':'','ExecStopPost':'',
                  'TimeoutStartUSec':'2min 30s','TimeoutStopUSec':'10s'}
        require(all(values.get(k)==v for k,v in expected.items()) and values.get('User') in ['', 'root'],
                'UNIT_RUNTIME_CONFLICT')
        return True

    def reset_own_unit(self):
        # Reject merged overrides before stopping a unit with a potentially foreign ExecStop.
        if self.unit_available(): self.run(['/usr/bin/systemctl','stop','uu-armada-compat.service'])

    def dnat(self,pkg):
        require(os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'),'NOT_HOST_NAMESPACE')
        # Only the isolated child gets a new anonymous network namespace. No mounts/veth/host rules.
        result=json.loads(self.run(['/usr/bin/unshare','--net','--', '/usr/bin/python3','-I','-B',
                                   str(pkg.path/'runtime/dnat.py'),os.readlink('/proc/self/ns/net')],timeout=35))
        require(result.get('complete') is True,'ISOLATED_DNAT_FAILED')
        labels={x.get('label') for x in result.get('tests',[]) if x.get('passed') or x.get('rc')==0 or x.get('packets')==1}
        require({'native_add','native_unmarked_redirected','native_marked_excluded',
                 'native_counter','native_delete','native_verify_removed','native_after_delete_original'}<=labels,
                'ISOLATED_DNAT_INCOMPLETE')

    def compare(self,before,after):
        require(before['boot_id']==after['boot_id'] and before['netns']==after['netns'],'HOST_IDENTITY_CHANGED')
        require(before['network']==after['network'] and before['firewall_effective_hash']==after['firewall_effective_hash'],
                'NETWORK_CHANGED')
        # Steam/Decky process creation is legitimate. Existing active services must remain active.
        for unit,value in before['services'].items():
            if 'ActiveState=active' in value:
                require('ActiveState=active' in after['services'][unit],'SERVICE_REGRESSED')
        if any(x['comm']=='uuplugin' for x in before['processes']):
            require(any(x['comm']=='uuplugin' for x in after['processes']),'UU_CORE_REGRESSED')
        require(after['taint'] in [before['taint'],before['taint']|4096],'NEW_KERNEL_TAINT')
        require(not p.kernel_log(before['cursor']),'NEW_KERNEL_ALERT')

    def observe(self,before):
        for i in range(3):
            if i: time.sleep(1)
            after=self.snapshot(); self.health(after); self.compare(before,after)

    def safe_unload(self,current,baseline):
        self.health(current)
        require(current['module'].get('refs')==0 and not current['module'].get('holders') and not current['tun'],
                'MODULE_OR_TUN_BUSY')
        # The historical pre-load network is NOT a permanent uninstall invariant.
        # Keep host/kernel health checks, but prove present rule independence instead.
        require(baseline['boot_id']==current['boot_id'] and baseline['netns']==current['netns'],
                'HOST_IDENTITY_CHANGED')
        require(current['taint'] in [baseline['taint'],baseline['taint']|4096],'NEW_KERNEL_TAINT')
        require(not p.kernel_log(baseline['cursor']),'NEW_KERNEL_ALERT')
        proof=current.get('unload_rules',{})
        require(proof.get('schema')==1 and proof.get('firewall_sha256')==current.get('firewall_hash')
                and proof.get('independent') is True and proof.get('reason')=='native_filter_only',
                'UNLOAD_RULES_UNPROVEN')
        # If UU is installed but stopped/failed unexpectedly, do not infer session cleanup.
        fields=dict(line.split('=',1) for line in current['services']['uuplugin.service'].splitlines() if '=' in line)
        if fields.get('LoadState')=='loaded':
            require(fields.get('ActiveState')=='active' and fields.get('SubState')=='running'
                    and int(fields.get('MainPID','0'))>0,'UU_SERVICE_UNHEALTHY')
            require(any(x.get('comm')=='uuplugin' for x in current['processes']),'UU_CORE_NOT_OBSERVED')

    def after_remove(self,before):
        after=self.snapshot()
        require(not after['module']['loaded'],'MODULE_REMOVE_FAILED')
        try: self.compare(before,after)
        except Failure as error:
            if error.code=='NETWORK_CHANGED': raise Failure('POST_UNLOAD_NETWORK_CHANGED') from error
            raise
        self.health(after)

    def diagnostic_identity(self):
        # Never return uname nodename or arbitrary os-release strings.
        u=os.uname()
        safe=lambda x: x if re.fullmatch(r'[A-Za-z0-9_.+\-]{1,100}',x) else 'redacted'
        ids=p.note_ids(Path('/sys/kernel/notes').read_bytes())
        return {'release':safe(u.release),'architecture':safe(u.machine),
                'kernel_build_ids':[x for x in ids if re.fullmatch('[0-9a-f]{8,128}',x)],
                'config_sha256':sha(gzip.decompress(Path('/proc/config.gz').read_bytes()))}

    def diagnostic_runtime(self):
        s=self.snapshot(); m=s['module']
        services={}
        for unit in [*p.SERVICES,'uu-armada-compat.service']:
            text=self.run(['/usr/bin/systemctl','show',unit,'-p','LoadState','-p','ActiveState','-p','SubState',
                           '-p','MainPID','-p','Result','-p','ExecMainStatus'])
            values=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
            allowed={'loaded','not-found','masked','error','active','inactive','failed','activating','deactivating',
                     'running','dead','exited','success','exit-code','signal','timeout','start','stop','condition'}
            services[unit]={k:(int(v) if v.isdigit() and len(v)<12 else v if v in allowed else 'unknown')
                            for k,v in values.items() if k in ['LoadState','ActiveState','SubState','MainPID','Result','ExecMainStatus']}
        return {'module_loaded':m['loaded'],'module_refs':m.get('refs'),'module_holder_count':len(m.get('holders',[])),
                'tun_count':len(s['tun']),'acceleration':'possibly_active' if s['tun'] else 'not_observed',
                'network_digests':s['network'],'effective_firewall_sha256':s['firewall_effective_hash'],
                'rule_count':s['rule_count'],'kernel_taint':s['taint'],
                'recent_kernel_alerts':p.kernel_log(),'services':services,
                'process_counts':{name:sum(x['comm']==name for x in s['processes']) for name in ['uuplugin','steam','Decky Clash']}}
