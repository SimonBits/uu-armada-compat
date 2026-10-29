# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic localhost packets only; invoked inside a fresh anonymous network namespace."""

import os,sys,socket,subprocess,json,signal,pathlib
signal.alarm(25)
ns=os.readlink('/proc/self/ns/net');assert ns!=sys.argv[1] and os.readlink('/proc/1/ns/net')==sys.argv[1]
assert socket.if_nameindex()==[(1,'lo')]
initial_taint=pathlib.Path('/proc/sys/kernel/tainted').read_text().strip()
r={'namespace':ns,'tests':[],'complete':False}
def run(label,args):
 q=subprocess.run(args,capture_output=True,text=True,timeout=5,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LC_ALL':'C'})
 assert len(q.stdout)+len(q.stderr)<65536
 r['tests'].append({'label':label,'rc':q.returncode,'stderr_sha256':__import__('hashlib').sha256(q.stderr.encode()).hexdigest()})
 assert pathlib.Path('/proc/sys/kernel/tainted').read_text().strip()==initial_taint,'new_taint'
 if q.returncode:raise RuntimeError(label)
 return q.stdout
try:
 run('isolated_loopback_up',['/usr/bin/ip','link','set','lo','up'])
 dest=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);original=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 dest.bind(('127.0.0.1',19053));original.bind(('127.0.0.2',53));dest.settimeout(1);original.settimeout(1)
 def packet(label,mark,receiver):
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
   if mark:s.setsockopt(socket.SOL_SOCKET,36,mark)
   s.sendto(b'UU_SYNTHETIC_NON_DNS',('127.0.0.2',53));body,addr=receiver.recvfrom(128)
   assert body==b'UU_SYNTHETIC_NON_DNS'
  r['tests'].append({'label':label,'passed':True})
 args=['OUTPUT','-p','udp','-m','udp','--dport','53','-m','mark','!','--mark','0x164','-j','DNAT','--to-destination','127.0.0.1:19053']
 for label,tool in [('native','/usr/bin/iptables')]:
  run(label+'_add',[tool,'-w','2','-t','nat','-I']+args)
  packet(label+'_unmarked_redirected',0,dest)
  packet(label+'_marked_excluded',356,original)
  read=json.loads(run(label+'_readback',['/usr/bin/nft','-j','list','chain','ip','nat','OUTPUT']))
  rules=[x['rule'] for x in read['nftables'] if 'rule' in x];assert len(rules)==1
  counters=[x['counter'] for x in rules[0]['expr'] if 'counter' in x];assert len(counters)==1 and counters[0]['packets']==1
  r['tests'].append({'label':label+'_counter','packets':counters[0]['packets']})
  run(label+'_delete',[tool,'-w','2','-t','nat','-D']+args)
  read=json.loads(run(label+'_verify_removed',['/usr/bin/nft','-j','list','chain','ip','nat','OUTPUT']))
  assert not any('rule' in x for x in read['nftables'])
  packet(label+'_after_delete_original',0,original)
 dest.close();original.close();r['complete']=True
except Exception:r['error']='ISOLATED_DNAT_FAILED'
print(json.dumps(r),flush=True)
raise SystemExit(0 if r['complete'] else 1)
