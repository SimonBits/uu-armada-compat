# SPDX-License-Identifier: GPL-2.0-only
"""Read-only probes adapted from clean-test R5. No R5 lifecycle code is shipped."""
import datetime, gzip, hashlib, json, os, re, stat, struct, subprocess
from pathlib import Path
BASE = Path(__file__).resolve().parent.parent
# Set only after exact kernel selection by LinuxHost.preflight.
EXPECTED = None
MODULE = Path('/sys/module/xt_nat')
POWER_SUPPLY_ROOT = Path('/sys/class/power_supply')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C'}
ALERT = re.compile(r'WARNING:|Oops|BUG:|Kernel panic|Call trace:|soft lockup|hard LOCKUP|hung task|I/O error|BTRFS.*(?:error|corrupt)', re.I)
SERVICES = ['uuplugin.service','plugin_loader.service','NetworkManager.service','systemd-resolved.service']
def command(args, timeout=8, input_text=None):
    q = subprocess.run(args, capture_output=True, text=True, input=input_text, timeout=timeout, env=ENV)
    need(q.returncode == 0, 'PROBE_COMMAND_FAILED')
    need(len(q.stdout) < 8*1024*1024, 'PROBE_OUTPUT_LIMIT')
    return q.stdout

class Stop(RuntimeError):
    pass

def need(ok, message):
    if not ok:
        raise Stop(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def digest(obj):
    return sha(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode())

def canon(x):
    if isinstance(x, dict):
        return {k: ({} if k == 'counter' else canon(v)) for k, v in x.items()
                if k not in ['handle', 'comment', 'expires']}
    if isinstance(x, list):
        return [canon(v) for v in x]
    return x

def semantic_rules(rows):
    # Permit only inert empty ACCEPT base chains/table shells left by UU.
    # Sets/maps/non-ACCEPT chains/all rules remain part of the strict digest.
    rules = [x['rule'] for x in rows if 'rule' in x]
    kept = []
    for x in rows:
        c = x.get('chain')
        if c and c.get('policy') == 'accept' and c.get('hook'):
            used = any(r.get('family') == c['family'] and r.get('table') == c['table']
                       and r.get('chain') == c['name'] for r in rules)
            if not used:
                continue
        kept.append(x)
    return [x for x in kept if 'table' not in x or any(
        k != 'table' and v.get('family') == x['table']['family']
        and v.get('table') == x['table']['name']
        for y in kept for k, v in y.items())]


def unload_rule_safety(rows):
    """Closed, read-only proof for a small native filter subset; no rule rewrites.

    Not a general nft interpreter. NAT, opaque xt expressions, jumps, sets/maps,
    and unreviewed objects fail closed even when module refcount currently is 0.
    The evidence hash binds this decision to the SAME ruleset used by snapshot.
    """
    result = {'schema': 1, 'firewall_sha256': digest(rows),
              'independent': False, 'reason': 'unknown_rule_structure'}
    tables, chains, rules = set(), {}, []
    if not isinstance(rows, list): return result
    for row in rows:
        if not isinstance(row, dict) or len(row) != 1: return result
        kind, obj = next(iter(row.items()))
        if not isinstance(obj, dict) or obj.get('family') not in ['ip', 'ip6', 'inet']: return result
        if kind == 'table':
            if set(obj) != {'family', 'name'} or not isinstance(obj['name'], str): return result
            key = (obj['family'], obj['name'])
            if key in tables: return result
            tables.add(key)
        elif kind == 'chain':
            if set(obj) != {'family', 'table', 'name', 'type', 'hook', 'prio', 'policy'}: return result
            if not all(isinstance(obj[x], str) for x in ['table', 'name']): return result
            key = (obj['family'], obj['table'], obj['name'])
            if key in chains or obj['type'] not in ['filter', 'nat']: return result
            if obj['hook'] not in ['input', 'output', 'forward', 'prerouting', 'postrouting']: return result
            if type(obj['prio']) is not int or obj['policy'] not in ['accept', 'drop']: return result
            chains[key] = obj
        elif kind == 'rule':
            if set(obj) != {'family', 'table', 'chain', 'expr'}: return result
            if not all(isinstance(obj[x], str) for x in ['table', 'chain']): return result
            rules.append(obj)
        else: return result
    if any(key[:2] not in tables for key in chains): return result
    for rule in rules:
        chain = chains.get((rule['family'], rule['table'], rule['chain']))
        if chain is None: return result
        if chain['type'] == 'nat':
            result['reason'] = 'active_nat_or_xt'; return result
        expr = rule['expr']
        if not isinstance(expr, list) or not expr: return result
        if any(isinstance(e, dict) and set(e) & {'xt', 'dnat', 'snat', 'masquerade', 'redirect'} for e in expr):
            result['reason'] = 'active_nat_or_xt'; return result
        if expr[-1] not in [{'accept': None}, {'drop': None}]: return result
        for e in expr[:-1]:
            if e == {'counter': {}}: continue
            if not isinstance(e, dict) or set(e) != {'match'}: return result
            m = e['match']
            if not isinstance(m, dict) or set(m) != {'op', 'left', 'right'} or m['op'] != '==': return result
            # Scalar RHS only: no map/set/expression evaluation or indirect targets.
            if type(m['right']) not in [str, int]: return result
            left = m['left']
            if not isinstance(left, dict) or len(left) != 1: return result
            if 'meta' in left:
                v = left['meta']
                if not isinstance(v, dict) or set(v) != {'key'} or v['key'] not in ['iifname', 'oifname', 'l4proto', 'nfproto']: return result
            elif 'payload' in left:
                v = left['payload']
                if not isinstance(v, dict) or set(v) != {'protocol', 'field'}: return result
                if (v['protocol'], v['field']) not in [('ip','saddr'),('ip','daddr'),('ip6','saddr'),('ip6','daddr'),('tcp','sport'),('tcp','dport'),('udp','sport'),('udp','dport')]: return result
            else: return result
    # Empty NAT base chains are inert only with ACCEPT policy.
    if any(c['type'] == 'nat' and c['policy'] != 'accept' for c in chains.values()): return result
    result.update(independent=True, reason='native_filter_only')
    return result

def note_ids(data):
    ids, pos = [], 0
    while pos + 12 <= len(data):
        ns, ds, kind = struct.unpack_from('<III', data, pos)
        pos += 12
        need(ns <= len(data) - pos, 'Invalid ELF note name')
        name = data[pos:pos+ns].rstrip(b'\0'); pos += (ns+3) & ~3
        need(ds <= len(data) - pos, 'Invalid ELF note descriptor')
        desc = data[pos:pos+ds]; pos += (ds+3) & ~3
        if name == b'GNU' and kind == 3:
            ids.append(desc.hex())
    return ids

def identity():
    u = os.uname()
    config = gzip.decompress(Path('/proc/config.gz').read_bytes())
    result = {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'machine': u.machine, 'release': u.release, 'version': u.version,
              'build_ids': note_ids(Path('/sys/kernel/notes').read_bytes()),
              'config_sha256': sha(config),
              'files': {p: sha(Path(p).read_bytes()) for p in EXPECTED['files']}}
    result['os_release'] = {k: v.strip().strip(chr(34)) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line for k, v in [line.split('=', 1)] if k in ['NAME', 'ID', 'VERSION_ID', 'BUILD_ID']}
    validate_identity(result)
    need(Path('/proc/sys/kernel/modules_disabled').read_text().strip() == '0', 'Module loading disabled')
    for path in ['/sys/kernel/security/lockdown', '/sys/module/module/parameters/sig_enforce']:
        p = Path(path)
        if p.exists():
            value = p.read_text().strip()
            need(value in ['N', '0'] or '[none]' in value, 'Unreviewed loading policy: ' + path)
    return result

def validate_identity(x):
    need(x['machine'] == 'aarch64' and x['release'] == EXPECTED['release'], 'Kernel arch/release mismatch')
    need(x['version'] == EXPECTED['uname_version'], 'Full kernel version mismatch')
    need(x['build_ids'] == [EXPECTED['kernel_build_id']], 'Running kernel Build ID mismatch')
    need(x['config_sha256'] == EXPECTED['config_sha256'], 'Running config mismatch')
    need(x['files'] == EXPECTED['files'], 'Kernel image/dependency fingerprint mismatch')

def kernel_log(cursor=None):
    args = ['/usr/bin/journalctl', '-k', '-b', '-o', 'json', '--no-pager', '--quiet']
    args += ['--after-cursor', cursor] if cursor else ['--since', '10 minutes ago']
    entries = [json.loads(l) for l in command(args).splitlines() if l]
    # Output hashes and times, never complete journal messages or unrelated data.
    return [{'monotonic': e.get('__MONOTONIC_TIMESTAMP'), 'sha256': sha(e['MESSAGE'].encode())}
            for e in entries if isinstance(e.get('MESSAGE'), str) and ALERT.search(e['MESSAGE'])]

def module_state():
    if not MODULE.exists():
        return {'loaded': False}
    return {'loaded': True, 'state': (MODULE/'initstate').read_text().strip(),
            'refs': int((MODULE/'refcnt').read_text()),
            'holders': sorted(x.name for x in (MODULE/'holders').iterdir()),
            'build_ids': note_ids((MODULE/'notes/.note.gnu.build-id').read_bytes())}

def snapshot():
    rows = [canon(x) for x in json.loads(command(['/usr/bin/nft', '-j', 'list', 'ruleset']))['nftables']
            if 'metainfo' not in x]
    network = {}
    for name, args in [('links', ['link']), ('routes', ['route', 'show', 'table', 'all']), ('rules', ['rule'])]:
        network[name] = digest(canon(json.loads(command(['/usr/bin/ip', '-j'] + args))))
    for name, args in [('routes6',['route','show','table','all']),('rules6',['rule'])]:
        network[name] = digest(canon(json.loads(command(['/usr/bin/ip','-6','-j']+args))))
    network['dns'] = sha(Path('/etc/resolv.conf').read_bytes())
    services = {s: command(['/usr/bin/systemctl', 'show', s, '-p', 'LoadState', '-p', 'ActiveState',
                           '-p', 'SubState', '-p', 'MainPID', '-p', 'NRestarts']).strip() for s in SERVICES}
    processes = []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            comm = (p/'comm').read_text().strip()
            if comm in ['uuplugin', 'steam', 'Decky Clash']:
                processes.append({'pid': int(p.name), 'comm': comm,
                                  'start_ticks': (p/'stat').read_text().rsplit(')', 1)[1].split()[19]})
        except FileNotFoundError:
            pass
    cursor = [json.loads(l) for l in command(['/usr/bin/journalctl', '-k', '-b', '-n', '1', '-o', 'json',
                                             '--no-pager', '--quiet']).splitlines() if l]
    need(bool(cursor), 'No kernel journal cursor')
    links = json.loads(command(['/usr/bin/ip', '-j', '-s', 'link']))
    tun = [x for x in links if Path('/sys/class/net', x['ifname'], 'tun_flags').exists()]
    return {'utc': now(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'netns': os.readlink('/proc/self/ns/net'), 'network': network, 'services': services,
            'processes': sorted(processes, key=lambda x: x['pid']),
            'firewall_hash': digest(rows), 'firewall_effective_hash': digest(semantic_rules(rows)),
            'rule_count': sum('rule' in x for x in rows),
            'unload_rules': unload_rule_safety(rows),
            'tun': [{k: x[k] for k in ['ifname', 'ifindex', 'stats64'] if k in x} for x in tun],
            'taint': int(Path('/proc/sys/kernel/tainted').read_text()),
            'cursor': cursor[-1]['__CURSOR'], 'module': module_state()}

def environmental_checks(s):
    need(s['netns'] == os.readlink('/proc/1/ns/net'), 'Run on host, not another network namespace')
    need(not s['taint'] & ~(512 | 4096), 'Unreviewed kernel taint')
    need(not kernel_log(), 'Recent serious kernel warning; review manually, no automatic override')
    need('ActiveState=active' in s['services']['NetworkManager.service'], 'NetworkManager not active')

def capabilities():
    status = Path('/proc/self/status').read_text()
    match = re.search(r'^CapEff:\s*([0-9a-fA-F]+)$', status, re.M)
    need(match is not None, 'Cannot read capability mask')
    return int(match[1], 16)

def power_status():
    """Read only sysfs power attributes; never infer supply type from its name."""
    external_types = {'Mains', 'UPS', 'USB', 'USB_DCP', 'USB_CDP', 'USB_ACA',
                      'USB_C', 'USB_PD', 'USB_PD_DRP', 'BrickID', 'Wireless'}
    supplies, external, batteries = [], [], []
    result = {'allowed': False, 'reason': 'POWER_STATE_UNKNOWN',
              'minimum_battery_percent': 20, 'external_online': None,
              'battery_percentages': batteries, 'supplies': supplies}
    try:
        entries = sorted(POWER_SUPPLY_ROOT.iterdir())
    except OSError as e:
        result['enumeration_errno'] = e.errno
        return result
    for supply in entries:
        row = {'name': supply.name, 'errors': {}}
        supplies.append(row)
        def read(attribute):
            try:
                value = (supply/attribute).read_text(encoding='ascii').strip()
            except (OSError, UnicodeError) as e:
                row['errors'][attribute] = getattr(e, 'errno', None)
                return None
            row[attribute] = value
            return value
        kind, scope = read('type'), read('scope')
        # scope is optional on older drivers. An explicit Device is peripheral-only.
        scope_ok = scope in ['System', 'Unknown'] or (scope is None and row['errors'].get('scope') == 2)
        if scope == 'Device':
            row['ignored'] = 'peripheral_supply'
            continue
        if not scope_ok:
            row['ignored'] = 'unreadable_or_invalid_scope'
            if kind == 'Battery':
                batteries.append(None)
            elif kind in external_types:
                external.append(None)
            continue
        if kind == 'Battery':
            present = read('present')
            if present == '0':
                row['ignored'] = 'battery_absent'
                continue
            # Kernel ABI: absent present attribute means battery is present.
            present_ok = present == '1' or (present is None and row['errors'].get('present') == 2)
            capacity = read('capacity')
            valid = (present_ok and capacity is not None
                     and re.fullmatch(r'[0-9]{1,3}', capacity) is not None
                     and 0 <= int(capacity) <= 100)
            batteries.append(int(capacity) if valid else None)
        elif kind in external_types:
            online = read('online')
            external.append(int(online) if online in ['0', '1', '2'] else None)
        else:
            row['ignored'] = 'unrecognized_supply_type'
    if any(value in [1, 2] for value in external):
        result.update(allowed=True, reason='EXTERNAL_POWER_ONLINE', external_online=True)
    else:
        result['external_online'] = False if external and all(value == 0 for value in external) else None
        if batteries and all(value is not None and value >= 20 for value in batteries):
            result.update(allowed=True, reason='BATTERY_AT_LEAST_20_PERCENT')
        elif any(value is not None and value < 20 for value in batteries):
            result['reason'] = 'BATTERY_BELOW_20_PERCENT_WITHOUT_CONFIRMED_EXTERNAL_POWER'
    return result
