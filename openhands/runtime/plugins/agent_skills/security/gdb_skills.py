"""GDB Skills - GDB调试和崩溃分析工具封装

提供GDB的Python接口，专门用于安全分析中的崩溃调试、可利用性评估等任务。
所有功能都专注于防御性安全分析。
"""

import os
import re
import subprocess
import tempfile
from typing import Optional


def analyze_crash(
    binary: str,
    crash_file: str,
    timeout: int = 30,
    include_disasm: bool = True,
    include_memory: bool = True,
) -> str:
    """使用GDB分析单个崩溃

    Args:
        binary: 二进制文件路径
        crash_file: 崩溃输入文件
        timeout: 分析超时时间
        include_disasm: 是否包含反汇编信息
        include_memory: 是否包含内存信息

    Returns:
        GDB分析结果
    """
    if not os.path.exists(binary):
        return f'错误：二进制文件 {binary} 不存在'

    if not os.path.exists(crash_file):
        return f'错误：崩溃文件 {crash_file} 不存在'

    # 构建GDB命令序列
    gdb_commands = [
        'set pagination off',
        'set confirm off',
        'set print elements 0',
        'set print repeats 0',
        f'file {binary}',
        f'run < {crash_file}',
        'bt',
        'info registers',
    ]

    if include_disasm:
        gdb_commands.extend(
            [
                'x/10i $rip',  # 显示当前指令和后续指令
                'x/10i $rip-40',  # 显示崩溃前的指令
            ]
        )

    if include_memory:
        gdb_commands.extend(
            [
                'x/20x $rsp',  # 显示栈内容
                'x/20x $rbp',  # 显示基址指针附近内容
                'info proc mappings',  # 显示内存映射
            ]
        )

    gdb_commands.append('quit')

    # 创建临时GDB脚本
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.gdb', delete=False
    ) as script_file:
        script_path = script_file.name
        script_file.write('\\n'.join(gdb_commands))

    try:
        # 执行GDB分析
        cmd = f'timeout {timeout} gdb -batch -x {script_path} 2>&1'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        output = result.stdout + result.stderr

        # 清理临时文件
        os.unlink(script_path)

        # 添加分析头信息
        analysis_header = f"""
=== GDB崩溃分析报告 ===
目标程序: {binary}
崩溃输入: {crash_file}
输入大小: {os.path.getsize(crash_file)} bytes
分析时间: {timeout}秒超时

=== GDB输出 ===
"""

        return analysis_header + output

    except Exception as e:
        # 确保清理临时文件
        if os.path.exists(script_path):
            os.unlink(script_path)
        return f'GDB分析失败: {str(e)}'


def batch_analyze_crashes(
    binary: str, crash_dir: str, max_crashes: int = 10, output_dir: Optional[str] = None
) -> str:
    """批量分析崩溃样本

    Args:
        binary: 二进制文件路径
        crash_dir: 崩溃目录路径
        max_crashes: 最大分析崩溃数量
        output_dir: 结果输出目录（可选）

    Returns:
        批量分析结果
    """
    if not os.path.exists(binary):
        return f'错误：二进制文件 {binary} 不存在'

    if not os.path.exists(crash_dir):
        return f'错误：崩溃目录 {crash_dir} 不存在'

    # 收集崩溃文件
    crash_files = []
    for root, dirs, files in os.walk(crash_dir):
        for file in files:
            if file.startswith('id:') and not file.endswith(('.analysis', '.log')):
                crash_files.append(os.path.join(root, file))

    if not crash_files:
        return f'在目录 {crash_dir} 中未找到崩溃文件'

    # 限制分析数量
    crash_files = crash_files[:max_crashes]

    results = []
    results.append(f'开始批量分析 {len(crash_files)} 个崩溃文件...')
    results.append('=' * 80)

    crash_summary = []

    for i, crash_file in enumerate(crash_files, 1):
        results.append(
            f'\\n分析崩溃 {i}/{len(crash_files)}: {os.path.basename(crash_file)}'
        )
        results.append('-' * 60)

        # 分析单个崩溃
        analysis = analyze_crash(binary, crash_file, timeout=20, include_disasm=False)
        results.append(analysis)

        # 提取关键信息用于摘要
        crash_info = extract_crash_info(analysis)
        crash_summary.append(
            {
                'file': os.path.basename(crash_file),
                'path': crash_file,
                'info': crash_info,
            }
        )

        # 如果指定了输出目录，保存单独的分析结果
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            analysis_file = os.path.join(
                output_dir, f'{os.path.basename(crash_file)}.analysis'
            )
            with open(analysis_file, 'w') as f:
                f.write(analysis)

    # 生成分析摘要
    results.append('\\n\\n' + '=' * 80)
    results.append('批量分析摘要')
    results.append('=' * 80)

    # 按信号类型分组
    signal_groups = {}
    for crash in crash_summary:
        signal = crash['info'].get('signal', 'Unknown')
        if signal not in signal_groups:
            signal_groups[signal] = []
        signal_groups[signal].append(crash)

    for signal, crashes in signal_groups.items():
        results.append(f'\\n{signal} ({len(crashes)} 个崩溃):')
        for crash in crashes[:5]:  # 每组最多显示5个
            results.append(
                f'  - {crash["file"]}: {crash["info"].get("crash_function", "Unknown")}'
            )
        if len(crashes) > 5:
            results.append(f'  ... 还有 {len(crashes) - 5} 个 {signal} 崩溃')

    if output_dir:
        results.append(f'\\n详细分析结果已保存到: {output_dir}')

    return '\\n'.join(results)


def extract_crash_info(gdb_output: str) -> dict[str, str]:
    """从GDB输出中提取关键崩溃信息

    Args:
        gdb_output: GDB分析输出

    Returns:
        包含关键信息的字典
    """
    info = {
        'signal': 'Unknown',
        'crash_address': 'Unknown',
        'crash_function': 'Unknown',
        'crash_instruction': 'Unknown',
        'stack_overflow': False,
        'heap_corruption': False,
        'control_hijack': False,
        'severity': 'Unknown',
    }

    # 提取信号类型
    signal_patterns = [
        r'Program received signal (\\w+)',
        r'Fatal signal (\\d+)',
        r'Terminated with signal (\\w+)',
    ]

    for pattern in signal_patterns:
        match = re.search(pattern, gdb_output)
        if match:
            info['signal'] = match.group(1)
            break

    # 提取崩溃地址和函数
    addr_patterns = [
        r'0x([0-9a-fA-F]+) in (\\w+)',
        r'=> 0x([0-9a-fA-F]+) <([^>]+)>',
        r'#0\\s+0x([0-9a-fA-F]+) in (\\w+)',
    ]

    for pattern in addr_patterns:
        match = re.search(pattern, gdb_output)
        if match:
            info['crash_address'] = '0x' + match.group(1)
            info['crash_function'] = match.group(2)
            break

    # 提取崩溃指令
    inst_patterns = [
        r'=>\\s+0x[0-9a-fA-F]+.*?:\\s+(.+?)$',
        r'Current PC:\\s+0x[0-9a-fA-F]+.*?:\\s+(.+?)$',
    ]

    for pattern in inst_patterns:
        match = re.search(pattern, gdb_output, re.MULTILINE)
        if match:
            info['crash_instruction'] = match.group(1).strip()
            break

    # 检查特定漏洞模式
    output_lower = gdb_output.lower()

    # 栈溢出检测
    stack_indicators = [
        'stack smashing detected',
        'stack-based buffer overflow',
        'stack overflow detected',
        '__stack_chk_fail',
    ]

    for indicator in stack_indicators:
        if indicator in output_lower:
            info['stack_overflow'] = True
            break

    # 堆损坏检测
    heap_indicators = [
        'malloc(): memory corruption',
        'double free or corruption',
        'free(): invalid pointer',
        'heap buffer overflow',
        'corrupted heap',
    ]

    for indicator in heap_indicators:
        if indicator in output_lower:
            info['heap_corruption'] = True
            break

    # 控制流劫持检测
    hijack_patterns = [
        r'rip.*0x[4-6]',  # RIP包含可能的用户控制数据
        r'rip.*0x[a-f]',
        r'pc.*0x[4-6]',
        r'eip.*0x[4-6]',
    ]

    for pattern in hijack_patterns:
        if re.search(pattern, output_lower):
            info['control_hijack'] = True
            break

    # 也检查明显的非法地址
    if any(
        addr in info['crash_address'].lower()
        for addr in ['41414141', '42424242', '43434343']
    ):
        info['control_hijack'] = True

    # 确定严重程度
    if info['control_hijack']:
        info['severity'] = 'Critical'
    elif info['stack_overflow'] or info['heap_corruption']:
        info['severity'] = 'High'
    elif info['signal'] in ['SIGSEGV', 'SIGBUS', 'SIGABRT']:
        info['severity'] = 'Medium'
    else:
        info['severity'] = 'Low'

    return info


def check_exploitability(binary: str, crash_file: str, timeout: int = 30) -> str:
    """检查崩溃的可利用性

    Args:
        binary: 二进制文件路径
        crash_file: 崩溃文件路径
        timeout: 分析超时时间

    Returns:
        可利用性评估结果
    """
    if not os.path.exists(binary):
        return f'错误：二进制文件 {binary} 不存在'

    if not os.path.exists(crash_file):
        return f'错误：崩溃文件 {crash_file} 不存在'

    # 首先进行基础崩溃分析
    crash_analysis = analyze_crash(binary, crash_file, timeout)
    crash_info = extract_crash_info(crash_analysis)

    exploitability_result = []
    exploitability_result.append('=== 可利用性评估报告 ===')
    exploitability_result.append(f'目标程序: {binary}')
    exploitability_result.append(f'崩溃输入: {crash_file}')
    exploitability_result.append(f'严重程度: {crash_info["severity"]}')
    exploitability_result.append('')

    # 尝试使用exploitable插件（如果可用）
    try:
        exploitable_cmd = f"echo 'source ~/.gdbinit\\nfile {binary}\\nrun < {crash_file}\\nexploitable\\nquit' | timeout {timeout} gdb -batch 2>&1"
        result = subprocess.run(
            exploitable_cmd, shell=True, capture_output=True, text=True
        )

        if (
            'exploitable' in result.stdout.lower()
            and 'not exploitable' not in result.stdout.lower()
        ):
            exploitability_result.append('=== Exploitable插件分析 ===')
            exploitability_result.append(result.stdout)
            exploitability_result.append('')

    except Exception:
        pass  # Exploitable插件不可用，继续手动分析

    # 手动可利用性分析
    exploitability_result.append('=== 手动可利用性分析 ===')

    # 分析控制流劫持
    if crash_info['control_hijack']:
        exploitability_result.append('✓ 控制流劫持检测: 可能')
        exploitability_result.append(f'  - 崩溃地址: {crash_info["crash_address"]}')
        exploitability_result.append('  - 风险: 攻击者可能控制指令指针')
        exploitability_result.append('  - 利用潜力: 高')
    else:
        exploitability_result.append('✗ 控制流劫持检测: 未发现')

    # 分析栈溢出
    if crash_info['stack_overflow']:
        exploitability_result.append('✓ 栈溢出检测: 确认')
        exploitability_result.append('  - 类型: 栈缓冲区溢出')
        exploitability_result.append('  - 风险: 可能覆盖返回地址或函数指针')
        exploitability_result.append('  - 利用潜力: 中到高')

    # 分析堆损坏
    if crash_info['heap_corruption']:
        exploitability_result.append('✓ 堆损坏检测: 确认')
        exploitability_result.append('  - 类型: 堆内存损坏')
        exploitability_result.append('  - 风险: 可能导致任意代码执行')
        exploitability_result.append('  - 利用潜力: 中到高')

    # 信号分析
    signal = crash_info['signal']
    if signal == 'SIGSEGV':
        exploitability_result.append('✓ 信号分析: SIGSEGV (段错误)')
        exploitability_result.append('  - 原因: 非法内存访问')
        exploitability_result.append('  - 可能影响: 拒绝服务或代码执行')
    elif signal == 'SIGABRT':
        exploitability_result.append('✓ 信号分析: SIGABRT (程序中止)')
        exploitability_result.append('  - 原因: 检测到内存损坏')
        exploitability_result.append('  - 可能影响: 拒绝服务')
    elif signal == 'SIGBUS':
        exploitability_result.append('✓ 信号分析: SIGBUS (总线错误)')
        exploitability_result.append('  - 原因: 内存对齐错误')
        exploitability_result.append('  - 可能影响: 拒绝服务')

    # 总体评估
    exploitability_result.append('')
    exploitability_result.append('=== 总体可利用性评估 ===')

    if crash_info['control_hijack']:
        exploitability_result.append('评估结果: 高度可利用')
        exploitability_result.append('建议: 立即修复，这是一个严重的安全漏洞')
    elif crash_info['stack_overflow'] or crash_info['heap_corruption']:
        exploitability_result.append('评估结果: 可能可利用')
        exploitability_result.append('建议: 需要进一步分析，应当优先修复')
    elif signal in ['SIGSEGV', 'SIGABRT', 'SIGBUS']:
        exploitability_result.append('评估结果: 可能导致拒绝服务')
        exploitability_result.append('建议: 修复以防止服务中断')
    else:
        exploitability_result.append('评估结果: 可利用性较低')
        exploitability_result.append('建议: 仍应修复以提高程序稳定性')

    exploitability_result.append('')
    exploitability_result.append('=== 基础崩溃分析 ===')
    exploitability_result.append(crash_analysis)

    return '\\n'.join(exploitability_result)


def generate_crash_report(
    binary: str, crash_files: list[str], output_file: Optional[str] = None
) -> str:
    """生成综合崩溃分析报告

    Args:
        binary: 二进制文件路径
        crash_files: 崩溃文件列表
        output_file: 输出文件路径（可选）

    Returns:
        报告内容或生成结果
    """
    if not crash_files:
        return '错误：未提供崩溃文件'

    report_lines = []
    report_lines.append('=' * 80)
    report_lines.append('综合崩溃分析报告')
    report_lines.append('=' * 80)
    report_lines.append(f'目标程序: {binary}')
    report_lines.append(f'分析文件数: {len(crash_files)}')
    report_lines.append(
        f'生成时间: {subprocess.run("date", shell=True, capture_output=True, text=True).stdout.strip()}'
    )
    report_lines.append('')

    # 统计信息
    crash_stats = {
        'total': len(crash_files),
        'analyzed': 0,
        'exploitable': 0,
        'high_severity': 0,
    }

    for i, crash_file in enumerate(crash_files):
        if not os.path.exists(crash_file):
            continue

        crash_stats['analyzed'] += 1

        report_lines.append(f'\\n### 崩溃 {i + 1}: {os.path.basename(crash_file)}')
        report_lines.append('-' * 50)

        # 分析崩溃
        analysis = analyze_crash(binary, crash_file, timeout=20)
        crash_info = extract_crash_info(analysis)

        # 统计严重程度
        if crash_info['severity'] in ['Critical', 'High']:
            crash_stats['high_severity'] += 1

        if crash_info['control_hijack']:
            crash_stats['exploitable'] += 1

        # 添加摘要信息
        report_lines.append(f'信号: {crash_info["signal"]}')
        report_lines.append(f'严重程度: {crash_info["severity"]}')
        report_lines.append(f'崩溃函数: {crash_info["crash_function"]}')
        report_lines.append(
            f'控制流劫持: {"是" if crash_info["control_hijack"] else "否"}'
        )
        report_lines.append(f'栈溢出: {"是" if crash_info["stack_overflow"] else "否"}')
        report_lines.append(
            f'堆损坏: {"是" if crash_info["heap_corruption"] else "否"}'
        )

    # 添加统计摘要
    report_lines.append('\\n\\n' + '=' * 80)
    report_lines.append('分析统计摘要')
    report_lines.append('=' * 80)
    report_lines.append(f'总崩溃数: {crash_stats["total"]}')
    report_lines.append(f'成功分析: {crash_stats["analyzed"]}')
    report_lines.append(f'高危漏洞: {crash_stats["high_severity"]}')
    report_lines.append(f'可利用崩溃: {crash_stats["exploitable"]}')
    report_lines.append(
        f'风险评级: {"高" if crash_stats["exploitable"] > 0 else "中" if crash_stats["high_severity"] > 0 else "低"}'
    )

    report_content = '\\n'.join(report_lines)

    # 如果指定了输出文件，写入文件
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_content)
            return f'崩溃分析报告已生成: {output_file}'
        except Exception as e:
            return f'报告生成失败: {str(e)}\\n\\n{report_content}'

    return report_content


# 导出的公共函数
__all__ = [
    'analyze_crash',
    'batch_analyze_crashes',
    'extract_crash_info',
    'check_exploitability',
    'generate_crash_report',
]
