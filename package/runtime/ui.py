# SPDX-License-Identifier: GPL-2.0-only
"""User-action guidance is separate from internal fault reporting."""
import os
from pathlib import Path
import shlex
import sys
from core import Failure

GUIDANCE = {
 'PACKAGE_PROFILES':'内核适配清单不完整或存在歧义，已停止。请核实可信安装包。',
 'UNIT_RECORD_MISMATCH':'单元文件与本工具安装记录的指纹不一致，已停止并保留现场。',
 'UNIT_FILE_PERMISSIONS':'本工具单元的所有者、组或权限不符合要求，已停止，不自动改写。',
 'STATE_INCONSISTENT':'安装记录与已验证版本或事务不一致，已停止并保留现场。',
 'GATHER_CALLER_UNKNOWN':'无法可靠识别原始调用用户。请从自己的终端使用 sudo 运行诊断命令。',
 'GATHER_OUTPUT_UNSAFE':'诊断输出目录不安全或不可用。请指定属于自己的、已存在且无符号链接的目录。',
 'GATHER_PACKAGE_DIRECTORY':'请把诊断包保存到安装包和工具状态目录之外，例如自己的家目录。',

 'ROOT_REQUIRED':'需要管理员权限，请使用以下命令：',
 'LOCAL_RECOVERY_REQUIRED':'尚未确认本地恢复能力。请在交互终端重新运行安装命令并完成确认。',
 'INTERACTIVE_CONFIRMATION_REQUIRED':'无法读取确认。请在本机或 SSH 交互终端运行以下命令：',
 'CONFIRMATION_DECLINED':'已取消，未开始安装操作。',
 'CONFIRMATION_INVALID':'未识别确认内容，未开始安装。请重新运行，输入 yes 或 no。',
 'OPERATION_BUSY':'另一个安装或卸载操作正在运行，请等待其结束后再试。',
 'POWER_UNSAFE':'供电条件不满足。请接入电源或确保主机电池至少 20%，再重试。',
 'KERNEL_IDENTITY_OR_POLICY':'当前内核或加载策略不匹配，已停止。请使用适配此内核的工具包，不要强制加载。',
 'DEPENDENCY_INTEGRITY':'系统依赖指纹不匹配，已停止。请使用匹配当前系统的工具包，不要替换或强制加载依赖。',
 'DEPENDENCY_ABI':'系统依赖 ABI 不匹配，已停止，不会强制加载。',
 'DEPENDENCY_RUNTIME_IDENTITY':'已加载依赖的身份不匹配，已停止，请人工核对。',
 'MODULE_ABI':'模块 ABI 不匹配，已停止，不会强制加载。',
 'MODULE_INTEGRITY':'模块完整性校验失败，已停止。请重新核实可信安装包。',
 'KERNEL_CONFIG':'当前内核配置不匹配，已停止。',
 'HOST_TOOL_ARCHITECTURE':'系统工具架构不符合要求，已停止，不会替换系统工具。',
 'REQUIRED_TOOL_UNAVAILABLE':'缺少必要的系统工具，已停止，不会自动安装软件。',
 'CAPABILITIES_REQUIRED':'当前环境不具备所需内核权限。请在设备本机管理员环境运行，不要绕过限制。',
 'USE_UPGRADE':'检测到其他已安装版本。请从新包执行升级命令：',
 'NOT_INSTALLED':'尚无完整安装，请先执行安装命令：',
 'CLEANUP_PENDING':'上次卸载尚未完成，请先继续安全卸载：',
 'RESUME_MODULE_CHANGE':'失败安装的模块与新包不同，不能直接续装。请先完成原版本安全卸载。',
 'DOWNGRADE_REFUSED':'不支持降级，请使用相同或更高版本的可信安装包。',
 'SAME_VERSION_DIFFERENT_PACKAGE':'相同版本的文件内容不同，已停止，保留现有文件。请核实安装包来源。',
 'UNIT_DROPIN_CONFLICT':'存在未认可的 systemd 覆盖配置，已停止。请保留配置并交由维护者审查，不要直接删除。',
 'UNIT_RUNTIME_CONFLICT':'同名 systemd 单元不属于本工具或运行配置不符，已停止，不会覆盖它。',
 'FOREIGN_UNIT':'已有同名单元内容不属于本工具，已停止，不会覆盖。',
 'FOREIGN_ENABLE_LINK':'已有同名启动链接不属于本工具，已停止，不会覆盖。',
 'FOREIGN_STORE':'目录不属于本工具，已停止，保留原文件。',
 'UNOWNED_MODULE':'xt_nat 已由其他流程加载。请先按原流程安全结束；不会重复加载或强制卸载。',
 'MODULE_OR_TUN_BUSY':'模块或 TUN 正在使用。请在手机上正常停止加速后重试；不会强制卸载。',
 'TUN_ACTIVE':'检测到活动 TUN。请先正常停止相关加速或隧道，再重试。',
 'RECOVERY_TUN_ACTIVE':'检测到活动 TUN，暂不能恢复安装。请先正常停止相关加速或隧道。',
 'UU_SERVICE_UNHEALTHY':'UU 服务状态异常，暂不卸载。请先人工确认 UU 状态。',
 'UU_CORE_NOT_OBSERVED':'未观察到 UU 核心，暂不卸载。请先人工确认 UU 状态。',
 'NETWORK_CHANGED':'操作期间网络或有效规则发生变化，已停止后续步骤。请人工核对；不会自动恢复规则。',
 'UNLOAD_RULES_UNPROVEN':'存在活动 NAT 规则或无法确认独立性的网络规则，暂不卸载；不会修改规则。',
 'POST_UNLOAD_NETWORK_CHANGED':'模块已卸载，但操作前后网络状态变化，已停止文件清退并保留记录。请人工核对；不会自动恢复规则。',
 'UNSAFE_OWNERSHIP':'文件所有权或权限不安全，已停止。请保留现场，勿直接覆盖或删除。',
 'UNSAFE_PATH':'路径状态不安全，已停止，保留原文件。',
 'PACKAGE_EXTRA_FILES':'安装包含有清单外文件，已停止。请使用完整、独立解压的可信安装包。',
 'PACKAGE_INTEGRITY':'安装包完整性校验失败，已停止。请重新核实可信安装包。',
 'PACKAGE_MANIFEST':'安装包校验清单缺失或无效，已停止。',
 'CLEANUP_UNKNOWN_FILES':'目录中存在未知文件，已停止清退并保留证据，不会删除它们。',
 'CLEANUP_MODIFIED_FILE':'待清退文件已被修改，已停止并保留证据。',
}

def sudo_command(base,action):
    name=action if action in ['install','upgrade','uninstall','status'] else 'status'
    path=('./'+name+'.sh') if Path.cwd().resolve()==Path(base).resolve() else str(Path(base)/(name+'.sh'))
    return 'sudo '+shlex.quote(path)

def confirm_recovery():
    prompt=('本操作将加载已验证的内核兼容模块并配置开机加载，仍可能卡死并需本机恢复。\n'
            '请确认重要数据已保存、本机终端或手动恢复可用。是否继续？[yes/no]：')
    terminal=None
    try:
        if sys.stdin.isatty(): source,target=sys.stdin,sys.stdout
        else:
            try: terminal=open('/dev/tty','r+',encoding='utf-8')
            except OSError: raise Failure('INTERACTIVE_CONFIRMATION_REQUIRED')
            source=target=terminal
        target.write(prompt); target.flush()
        reply=source.readline()
        if not reply: raise Failure('CONFIRMATION_DECLINED')
        answer=reply.strip().casefold()
        if answer in ['yes','y','是','确认']: return True
        if answer in ['','no','n','否','取消']: raise Failure('CONFIRMATION_DECLINED')
        raise Failure('CONFIRMATION_INVALID')
    except (KeyboardInterrupt,EOFError): raise Failure('CONFIRMATION_DECLINED')
    finally:
        if terminal is not None: terminal.close()

def show_error(code,base,action):
    message=GUIDANCE.get(code)
    if message:
        print(message,file=sys.stderr)
        command_action={'USE_UPGRADE':'upgrade','NOT_INSTALLED':'install','CLEANUP_PENDING':'uninstall'}.get(code,action)
        if code in ['ROOT_REQUIRED','INTERACTIVE_CONFIRMATION_REQUIRED','USE_UPGRADE','NOT_INSTALLED','CLEANUP_PENDING']:
            print(sudo_command(base,command_action),file=sys.stderr)
        return False
    print('兼容工具发生故障（'+code+'），未完成操作。请运行以下命令生成诊断报告：',file=sys.stderr)
    print(sudo_command(base,'status')+' --must-gather',file=sys.stderr)
    return True
