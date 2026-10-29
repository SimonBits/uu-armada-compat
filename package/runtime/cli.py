#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
"""Chinese user interface, fixed English error codes. No raw exceptions printed."""
import argparse
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from core import Package,Manager,Failure,require,diagnostic,gather,utc,VERSION
from host import LinuxHost
from diagnostic_output import write_report
from ui import confirm_recovery,show_error,GUIDANCE

MESSAGES={
 'ALREADY_INSTALLED':'已安装，无需重复操作。',
 'RECOVERED':'已安全恢复上次安装并完成验证；未重复加载已就绪的模块。',
 'INSTALLED':'安装完成，已配置开机加载。隔离 DNAT 验证通过，可在手机 App 中手动测试 UU。',
 'UPGRADED':'离线升级完成。', 'NO_UPGRADE':'当前版本相同，无需升级。',
 'UNINSTALLED':'卸载完成。私有诊断记录已保留；未删除 UU 或系统依赖。',
 'ALREADY_UNINSTALLED':'未安装，无需重复卸载。',
 'NATIVE_PROVIDER':'系统已提供原生 NAT 兼容能力，跳过外部模块部署；未验证 UU 实际加速。',
 'BOOT_READY':'兼容组件已就绪。',
}

def main():
    parser=argparse.ArgumentParser(description='UU Armada 兼容工具 0.1.0（离线）')
    parser.add_argument('action',choices=['install','upgrade','uninstall','status','boot','boot-check'])
    parser.add_argument('--confirm-local-recovery',action='store_true',help='确认本地终端可用、数据已保存，并接受本工具开机加载')
    parser.add_argument('--must-gather',action='store_true',help='生成白名单英文诊断压缩包')
    parser.add_argument('--output-dir',help='诊断包输出目录（已存在且属于原始调用用户；默认家目录）')
    args=parser.parse_args()
    if args.must_gather and args.action!='status': parser.error('--must-gather 仅适用于 status')
    if args.output_dir and not (args.action=='status' and args.must_gather): parser.error('--output-dir 仅适用于 status --must-gather')
    base=Path(__file__).resolve().parent.parent
    if os.geteuid()!=0:
        show_error('ROOT_REQUIRED',base,args.action)
        return 2
    host=LinuxHost(); manager=Manager(host)
    try:
        require(os.geteuid()==0,'ROOT_REQUIRED')
        pkg=Package(Path(__file__).resolve().parent.parent)
        require(pkg.version==VERSION,'CONTROL_VERSION_MISMATCH')
        if args.action=='status':
            report=diagnostic(host,manager,pkg)
            try:
                if host.native_provider(): compatibility='系统原生支持'
                else: host.preflight(pkg); compatibility='匹配'
            except Exception: compatibility='不匹配或检查未通过'
            runtime=report['sections'].get('runtime',{})
            print('内核兼容性：'+compatibility)
            print('xt_nat：'+('已加载' if runtime.get('module_loaded') else '未加载' if 'module_loaded' in runtime else '未知'))
            services=runtime.get('services',{})
            labels={'active':'正常','inactive':'未运行','failed':'失败','activating':'启动中',
                    'deactivating':'停止中','unknown':'未知'}
            state_label=lambda unit:labels.get(services.get(unit,{}).get('ActiveState','unknown'),'未知')
            try: enabled=manager.enable_link()
            except Failure: enabled=False
            print('开机加载：'+('已配置' if enabled else '未配置')+'；服务状态：'+state_label('uu-armada-compat.service'))
            print('UU 服务：'+state_label('uuplugin.service'))
            print('加速状态：'+('观察到 TUN，需用手机和实际流量确认' if runtime.get('tun_count',0)>0 else '未观察到 TUN 或信息不足'))
            if args.must_gather:
                report['sections']['compatibility']={'check_passed':compatibility in ['匹配','系统原生支持']}
                path=write_report(report,pkg.path,manager.store,args.output_dir)
                print('诊断包已生成：'+str(path))
            if report['errors']:
                print('部分检查未完成，请查看诊断包中的错误代码。'); return 1
            return 0 if compatibility in ['匹配','系统原生支持'] else 1
        if args.action in ['install','upgrade']:
            confirmed=args.confirm_local_recovery
            if not confirmed: confirmed=confirm_recovery()
            result=manager.install(pkg,confirmed,upgrade=args.action=='upgrade')
        elif args.action=='uninstall': result=manager.uninstall()
        elif args.action=='boot-check':
            result=manager.boot_check(pkg)
            if result=='NATIVE_PROVIDER': print('BOOT_SKIPPED_NATIVE_PROVIDER'); return 1
            print('BOOT_CHECK_PASSED'); return 0
        else: result=manager.boot(pkg)
        print(result if args.action=='boot' else MESSAGES[result]); return 0
    except Exception as exc:
        code=exc.code if isinstance(exc,Failure) else 'INTERNAL_OR_IO_ERROR'
        if args.action=='boot-check':
            print('BOOT_SKIPPED '+code)
            return 1  # ExecCondition skip, no failed dependency propagation or retry.
        if args.action in ['boot']:
            print('BOOT_FAILED '+code)
        else:
            show_error(code,base,args.action)
        # Never create an empty installation for an input/permission error.
        # Only an existing, validated private store can receive fault evidence.
        if args.action!='status' and code not in ['ROOT_REQUIRED','LOCAL_RECOVERY_REQUIRED',
                'INTERACTIVE_CONFIRMATION_REQUIRED','CONFIRMATION_DECLINED','CONFIRMATION_INVALID','OPERATION_BUSY'] and manager.store.exists():
            try:
                manager.state(); manager.event('OPERATION_FAILED',error_code=code,rc=getattr(exc,'rc',None))
            except Exception: pass
        if code=='CONFIRMATION_DECLINED': return 0
        if code in GUIDANCE: return 2
        return 1

if __name__=='__main__': sys.exit(main())
