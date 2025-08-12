"""Analysis Skills - 通用安全分析工具封装

提供二进制安全特性检查、函数分析、危险函数识别和报告生成等通用安全分析功能。
所有功能都专注于防御性安全分析。
"""

import datetime
import json
import os
import re
import subprocess
from typing import Any, Optional


def check_binary_security(binary: str, detailed: bool = True) -> str:
    """检查二进制文件的安全特性

    Args:
        binary: 二进制文件路径
        detailed: 是否显示详细信息

    Returns:
        安全特性检查结果
    """
    if not os.path.exists(binary):
        return f'错误：二进制文件 {binary} 不存在'

    results = []
    results.append('=== 二进制安全特性分析 ===')
    results.append(f'目标文件: {binary}')
    results.append(f'文件大小: {os.path.getsize(binary)} bytes')
    results.append('')

    # 基础文件信息
    results.append('=== 基础文件信息 ===')
    try:
        file_cmd = f'file {binary}'
        file_result = subprocess.run(
            file_cmd, shell=True, capture_output=True, text=True
        )
        if file_result.returncode == 0:
            results.append(file_result.stdout.strip())
        else:
            results.append('无法获取文件类型信息')
    except Exception as e:
        results.append(f'文件类型检查失败: {str(e)}')

    results.append('')

    # 使用checksec检查安全特性
    results.append('=== 安全特性检查 ===')
    try:
        checksec_cmd = f'checksec --file={binary}'
        checksec_result = subprocess.run(
            checksec_cmd, shell=True, capture_output=True, text=True, timeout=30
        )

        if checksec_result.returncode == 0:
            results.append('使用checksec工具检查:')
            results.append(checksec_result.stdout.strip())
        else:
            results.append('checksec工具不可用，执行手动检查...')
            manual_check = _manual_security_check(binary)
            results.append(manual_check)

    except subprocess.TimeoutExpired:
        results.append('checksec检查超时，执行手动检查...')
        manual_check = _manual_security_check(binary)
        results.append(manual_check)
    except Exception as e:
        results.append(f'checksec检查失败: {str(e)}')
        results.append('执行手动检查...')
        manual_check = _manual_security_check(binary)
        results.append(manual_check)

    # 详细分析
    if detailed:
        results.append('\\n=== 详细安全分析 ===')

        # 检查动态链接库
        results.append('\\n动态链接库依赖:')
        try:
            ldd_cmd = f'ldd {binary}'
            ldd_result = subprocess.run(
                ldd_cmd, shell=True, capture_output=True, text=True
            )
            if ldd_result.returncode == 0:
                libs = ldd_result.stdout.strip().split('\\n')[:10]  # 只显示前10个
                for lib in libs:
                    results.append(f'  {lib.strip()}')
                if len(ldd_result.stdout.strip().split('\\n')) > 10:
                    results.append(
                        f'  ... 还有 {len(ldd_result.stdout.strip().split("\\n")) - 10} 个库'
                    )
            else:
                results.append('  无法获取动态链接库信息（可能是静态链接）')
        except Exception:
            results.append('  动态链接库检查失败')

        # 检查段信息
        results.append('\\n程序段信息:')
        try:
            readelf_cmd = f'readelf -l {binary}'
            readelf_result = subprocess.run(
                readelf_cmd, shell=True, capture_output=True, text=True
            )
            if readelf_result.returncode == 0:
                # 提取关键段信息
                sections = []
                for line in readelf_result.stdout.split('\\n'):
                    if 'LOAD' in line or 'GNU_STACK' in line or 'GNU_RELRO' in line:
                        sections.append(f'  {line.strip()}')

                if sections:
                    for section in sections[:5]:  # 只显示前5个关键段
                        results.append(section)
                else:
                    results.append('  未找到关键段信息')
            else:
                results.append('  无法获取段信息')
        except Exception:
            results.append('  段信息检查失败')

    return '\\n'.join(results)


def _manual_security_check(binary: str) -> str:
    """手动安全特性检查（当checksec不可用时）"""
    results = []
    results.append('手动安全特性检查:')

    try:
        # 检查NX位（不可执行栈）
        nx_cmd = f'readelf -l {binary} | grep GNU_STACK'
        nx_result = subprocess.run(nx_cmd, shell=True, capture_output=True, text=True)

        if nx_result.returncode == 0 and nx_result.stdout:
            if 'RW ' in nx_result.stdout and 'RWE' not in nx_result.stdout:
                results.append('  NX: 启用 ✓')
            else:
                results.append('  NX: 禁用 ✗')
        else:
            results.append('  NX: 无法检测')

        # 检查PIE（位置无关执行）
        pie_cmd = f"readelf -h {binary} | grep 'Type:'"
        pie_result = subprocess.run(pie_cmd, shell=True, capture_output=True, text=True)

        if pie_result.returncode == 0:
            if 'DYN' in pie_result.stdout:
                results.append('  PIE: 启用 ✓')
            elif 'EXEC' in pie_result.stdout:
                results.append('  PIE: 禁用 ✗')
            else:
                results.append('  PIE: 无法检测')
        else:
            results.append('  PIE: 检测失败')

        # 检查RELRO（重定位只读）
        relro_cmd = f'readelf -l {binary} | grep GNU_RELRO'
        relro_result = subprocess.run(
            relro_cmd, shell=True, capture_output=True, text=True
        )

        if relro_result.returncode == 0 and relro_result.stdout:
            # 进一步检查是否为Full RELRO
            bind_cmd = f'readelf -d {binary} | grep BIND_NOW'
            bind_result = subprocess.run(
                bind_cmd, shell=True, capture_output=True, text=True
            )

            if bind_result.returncode == 0 and bind_result.stdout:
                results.append('  RELRO: Full ✓')
            else:
                results.append('  RELRO: Partial ⚠')
        else:
            results.append('  RELRO: 禁用 ✗')

        # 检查栈保护
        canary_cmd = f'objdump -T {binary} | grep __stack_chk_fail'
        canary_result = subprocess.run(
            canary_cmd, shell=True, capture_output=True, text=True
        )

        if canary_result.returncode == 0 and canary_result.stdout.strip():
            results.append('  Stack Canary: 启用 ✓')
        else:
            results.append('  Stack Canary: 禁用 ✗')

    except Exception as e:
        results.append(f'  手动检查失败: {str(e)}')

    return '\\n'.join(results)


def extract_functions(binary: str, max_functions: int = 100) -> str:
    """提取二进制文件中的函数列表

    Args:
        binary: 二进制文件路径
        max_functions: 最大显示函数数量

    Returns:
        函数列表信息
    """
    if not os.path.exists(binary):
        return f'错误：二进制文件 {binary} 不存在'

    results = []
    results.append('=== 函数提取分析 ===')
    results.append(f'目标文件: {binary}')
    results.append('')

    all_functions = []

    # 方法1：使用objdump提取函数符号
    try:
        objdump_cmd = (
            f"objdump -t {binary} | grep -E ' F .text' | awk '{{print $NF}}' | sort"
        )
        objdump_result = subprocess.run(
            objdump_cmd, shell=True, capture_output=True, text=True
        )

        if objdump_result.returncode == 0 and objdump_result.stdout.strip():
            objdump_functions = [
                f.strip()
                for f in objdump_result.stdout.strip().split('\\n')
                if f.strip()
            ]
            all_functions.extend([(f, 'symbol') for f in objdump_functions])
            results.append(f'从符号表提取到 {len(objdump_functions)} 个函数')
        else:
            results.append('符号表函数提取失败')
    except Exception as e:
        results.append(f'符号表函数提取异常: {str(e)}')

    # 方法2：使用readelf提取动态符号
    try:
        readelf_cmd = f"readelf -Ws {binary} | grep FUNC | awk '{{print $8}}' | sort"
        readelf_result = subprocess.run(
            readelf_cmd, shell=True, capture_output=True, text=True
        )

        if readelf_result.returncode == 0 and readelf_result.stdout.strip():
            readelf_functions = [
                f.strip()
                for f in readelf_result.stdout.strip().split('\\n')
                if f.strip()
            ]
            # 去重合并
            existing_names = {name for name, _ in all_functions}
            new_functions = [f for f in readelf_functions if f not in existing_names]
            all_functions.extend([(f, 'dynamic') for f in new_functions])
            results.append(f'从动态符号表额外提取到 {len(new_functions)} 个函数')
        else:
            results.append('动态符号表函数提取失败')
    except Exception as e:
        results.append(f'动态符号表函数提取异常: {str(e)}')

    # 方法3：使用nm工具（如果可用）
    try:
        nm_cmd = f"nm {binary} | grep ' T ' | awk '{{print $3}}' | sort"
        nm_result = subprocess.run(nm_cmd, shell=True, capture_output=True, text=True)

        if nm_result.returncode == 0 and nm_result.stdout.strip():
            nm_functions = [
                f.strip() for f in nm_result.stdout.strip().split('\\n') if f.strip()
            ]
            existing_names = {name for name, _ in all_functions}
            new_functions = [f for f in nm_functions if f not in existing_names]
            all_functions.extend([(f, 'nm') for f in new_functions])
            results.append(f'从nm工具额外提取到 {len(new_functions)} 个函数')
    except Exception:
        pass  # nm工具可能不可用，跳过

    if not all_functions:
        return '\\n'.join(
            results + ['\\n未能提取到任何函数信息，可能是stripped binary']
        )

    # 统计和分类
    results.append(f'\\n总共发现 {len(all_functions)} 个函数')

    # 分类统计
    categories = {}
    for func_name, source in all_functions:
        if source not in categories:
            categories[source] = 0
        categories[source] += 1

    results.append('\\n按来源分类:')
    for source, count in categories.items():
        results.append(f'  {source}: {count} 个')

    # 显示函数列表（限制数量）
    results.append(f'\\n前 {min(max_functions, len(all_functions))} 个函数:')
    for i, (func_name, source) in enumerate(all_functions[:max_functions]):
        results.append(f'  {i + 1:3d}. {func_name} [{source}]')

    if len(all_functions) > max_functions:
        results.append(f'\\n... 还有 {len(all_functions) - max_functions} 个函数未显示')

    # 识别特殊函数
    special_functions = []
    for func_name, source in all_functions:
        if func_name in ['main', '_start', '__libc_start_main']:
            special_functions.append(f'{func_name} [入口函数]')
        elif 'init' in func_name.lower() or 'fini' in func_name.lower():
            special_functions.append(f'{func_name} [初始化函数]')
        elif 'constructor' in func_name.lower() or 'destructor' in func_name.lower():
            special_functions.append(f'{func_name} [构造/析构函数]')

    if special_functions:
        results.append('\\n特殊函数:')
        for func in special_functions:
            results.append(f'  • {func}')

    return '\\n'.join(results)


def find_dangerous_functions(binary: str, include_moderate: bool = True) -> str:
    """查找潜在危险函数的使用

    Args:
        binary: 二进制文件路径
        include_moderate: 是否包含中等风险函数

    Returns:
        危险函数使用分析结果
    """
    if not os.path.exists(binary):
        return f'错误：二进制文件 {binary} 不存在'

    # 定义危险函数分类
    critical_functions = [
        'gets',
        'strcpy',
        'strcat',
        'sprintf',
        'vsprintf',
        'scanf',
        'fscanf',
        'sscanf',
        'vscanf',
        'vfscanf',
        'vsscanf',
    ]

    high_risk_functions = [
        'strtok',
        'strtok_r',
        'strncpy',
        'strncat',
        'snprintf',
        'vsnprintf',
        'memcpy',
        'memmove',
        'bcopy',
        'system',
        'popen',
        'execve',
        'execl',
        'execlp',
        'execle',
        'execv',
        'execvp',
    ]

    moderate_risk_functions = [
        'malloc',
        'free',
        'realloc',
        'calloc',
        'alloca',
        'printf',
        'fprintf',
        'vprintf',
        'vfprintf',
        'fopen',
        'fread',
        'fwrite',
        'fseek',
        'ftell',
    ]

    results = []
    results.append('=== 危险函数使用分析 ===')
    results.append(f'目标文件: {binary}')
    results.append('')

    found_functions: dict[str, list[str]] = {'critical': [], 'high': [], 'moderate': []}

    # 检查导入的函数（动态链接）
    try:
        import_cmd = f"objdump -T {binary} 2>/dev/null | grep -E 'FUNC|UND'"
        import_result = subprocess.run(
            import_cmd, shell=True, capture_output=True, text=True
        )

        if import_result.returncode == 0:
            import_lines = import_result.stdout.strip().split('\\n')

            for line in import_lines:
                # 检查关键函数
                for func in critical_functions:
                    if re.search(r'\\b' + func + r'\\b', line):
                        found_functions['critical'].append(
                            f'{func} (导入函数): {line.strip()}'
                        )

                # 检查高风险函数
                for func in high_risk_functions:
                    if re.search(r'\\b' + func + r'\\b', line):
                        found_functions['high'].append(
                            f'{func} (导入函数): {line.strip()}'
                        )

                # 检查中等风险函数
                if include_moderate:
                    for func in moderate_risk_functions:
                        if re.search(r'\\b' + func + r'\\b', line):
                            found_functions['moderate'].append(
                                f'{func} (导入函数): {line.strip()}'
                            )

    except Exception as e:
        results.append(f'导入函数检查失败: {str(e)}')

    # 检查PLT表中的函数调用
    try:
        plt_cmd = f"objdump -d {binary} | grep '@plt'"
        plt_result = subprocess.run(plt_cmd, shell=True, capture_output=True, text=True)

        if plt_result.returncode == 0:
            plt_lines = plt_result.stdout.strip().split('\\n')

            for line in plt_lines:
                # 检查关键函数
                for func in critical_functions:
                    if f'{func}@plt' in line:
                        found_functions['critical'].append(
                            f'{func} (PLT调用): {line.strip()}'
                        )

                # 检查高风险函数
                for func in high_risk_functions:
                    if f'{func}@plt' in line:
                        found_functions['high'].append(
                            f'{func} (PLT调用): {line.strip()}'
                        )

                # 检查中等风险函数
                if include_moderate:
                    for func in moderate_risk_functions:
                        if f'{func}@plt' in line:
                            found_functions['moderate'].append(
                                f'{func} (PLT调用): {line.strip()}'
                            )

    except Exception as e:
        results.append(f'PLT函数检查失败: {str(e)}')

    # 生成报告
    total_dangerous = (
        len(found_functions['critical'])
        + len(found_functions['high'])
        + len(found_functions['moderate'])
    )

    if total_dangerous == 0:
        results.append('✓ 未发现明显的危险函数使用')
        return '\\n'.join(results)

    results.append(f'发现 {total_dangerous} 个潜在危险函数使用')
    results.append('')

    # 关键风险函数
    if found_functions['critical']:
        results.append('=== 关键风险函数 (立即修复) ===')
        critical_set = set()
        for func_info in found_functions['critical']:
            func = func_info.split(' (')[0]  # 提取函数名
            if func not in critical_set:
                critical_set.add(func)
                results.append(f'⚠️  {func}')
                results.append('   风险: 极高 - 容易导致缓冲区溢出')
                if func == 'gets':
                    results.append('   建议: 使用 fgets() 替代')
                elif func in ['strcpy', 'strcat']:
                    results.append(
                        f'   建议: 使用 strn{func[3:]}() 或 strlc{func[3:]}() 替代'
                    )
                elif func in ['sprintf', 'vsprintf']:
                    results.append('   建议: 使用 snprintf() 或 vsnprintf() 替代')
                elif func in ['scanf', 'fscanf', 'sscanf']:
                    results.append('   建议: 限制输入长度或使用更安全的输入函数')
                results.append('')

    # 高风险函数
    if found_functions['high']:
        results.append('=== 高风险函数 (优先修复) ===')
        high_set = set()
        for func_info in found_functions['high']:
            func = func_info.split(' (')[0]  # 提取函数名
            if func not in high_set:
                high_set.add(func)
                results.append(f'⚠️  {func}')
                if func in ['strncpy', 'strncat']:
                    results.append('   风险: 可能不会null终止字符串')
                    results.append('   建议: 确保字符串正确终止')
                elif func in ['memcpy', 'memmove', 'bcopy']:
                    results.append('   风险: 可能导致缓冲区溢出')
                    results.append('   建议: 严格检查长度参数')
                elif func == 'system':
                    results.append('   风险: 命令注入攻击')
                    results.append('   建议: 使用 execve() 系列函数')
                elif func.startswith('exec'):
                    results.append('   风险: 代码执行，输入验证不当可能被利用')
                    results.append('   建议: 严格验证所有输入参数')
                results.append('')

    # 中等风险函数
    if include_moderate and found_functions['moderate']:
        results.append('=== 中等风险函数 (建议审查) ===')
        moderate_set = set()
        for func_info in found_functions['moderate']:
            func = func_info.split(' (')[0]  # 提取函数名
            if func not in moderate_set:
                moderate_set.add(func)
                results.append(f'ℹ️  {func}')
                if func in ['malloc', 'free', 'realloc', 'calloc']:
                    results.append('   建议: 检查内存分配/释放错误，防止内存泄漏')
                elif func in ['printf', 'fprintf', 'vprintf', 'vfprintf']:
                    results.append('   建议: 使用固定格式字符串，防止格式化字符串攻击')
                elif func in ['fopen', 'fread', 'fwrite']:
                    results.append('   建议: 验证文件路径，检查返回值')
                results.append('')

    # 安全建议
    results.append('=== 安全加固建议 ===')
    results.append('1. 启用编译器安全选项:')
    results.append('   -fstack-protector-all (栈保护)')
    results.append('   -D_FORTIFY_SOURCE=2 (缓冲区溢出检测)')
    results.append('   -fPIE -pie (位置无关执行)')
    results.append('   -Wl,-z,relro,-z,now (完整RELRO)')
    results.append('')
    results.append('2. 使用静态分析工具进行进一步检查')
    results.append('3. 实施输入验证和边界检查')
    results.append('4. 考虑使用内存安全的编程语言重写关键模块')

    return '\\n'.join(results)


def generate_security_report(
    binary: str,
    analysis_results: Optional[dict[str, Any]] = None,
    output_file: Optional[str] = None,
    report_format: str = 'markdown',
) -> str:
    """生成综合安全分析报告

    Args:
        binary: 二进制文件路径
        analysis_results: 分析结果字典（可选）
        output_file: 输出文件路径（可选）
        report_format: 报告格式（markdown, text, json）

    Returns:
        报告内容或生成结果
    """
    if not os.path.exists(binary):
        return f'错误：二进制文件 {binary} 不存在'

    # 收集基础信息
    report_data = {
        'target': binary,
        'timestamp': datetime.datetime.now().isoformat(),
        'file_size': os.path.getsize(binary),
        'analysis_results': analysis_results or {},
    }

    # 执行快速安全检查
    security_check = check_binary_security(binary, detailed=False)
    dangerous_funcs = find_dangerous_functions(binary, include_moderate=False)

    if report_format == 'json':
        # JSON格式报告
        report_content = json.dumps(report_data, indent=2, ensure_ascii=False)

    elif report_format == 'markdown':
        # Markdown格式报告
        report_lines = []
        report_lines.append('# 安全分析报告')
        report_lines.append('')
        report_lines.append(f'**目标程序**: `{binary}`')
        report_lines.append(f'**文件大小**: {report_data["file_size"]} bytes')
        report_lines.append(f'**分析时间**: {report_data["timestamp"]}')
        report_lines.append('')

        # 执行摘要
        report_lines.append('## 执行摘要')
        report_lines.append('')

        # 简单的风险评估
        if '关键风险函数' in dangerous_funcs:
            risk_level = '🔴 高危'
        elif '高风险函数' in dangerous_funcs:
            risk_level = '🟡 中危'
        else:
            risk_level = '🟢 低危'

        report_lines.append(f'**风险级别**: {risk_level}')
        report_lines.append('')

        # 主要发现
        report_lines.append('## 主要发现')
        report_lines.append('')
        report_lines.append('### 二进制安全特性')
        report_lines.append('```')
        report_lines.append(security_check)
        report_lines.append('```')
        report_lines.append('')

        report_lines.append('### 危险函数分析')
        report_lines.append('```')
        report_lines.append(dangerous_funcs)
        report_lines.append('```')
        report_lines.append('')

        # 包含分析结果
        if analysis_results:
            report_lines.append('## 详细分析结果')
            report_lines.append('')

            for section, content in analysis_results.items():
                report_lines.append(f'### {section}')
                report_lines.append('')
                if isinstance(content, str):
                    report_lines.append('```')
                    report_lines.append(content)
                    report_lines.append('```')
                else:
                    report_lines.append(
                        f'```json\\n{json.dumps(content, indent=2)}\\n```'
                    )
                report_lines.append('')

        # 建议
        report_lines.append('## 安全建议')
        report_lines.append('')
        report_lines.append('1. **立即修复关键风险函数**')
        report_lines.append('   - 替换不安全的字符串处理函数')
        report_lines.append('   - 添加输入长度验证')
        report_lines.append('')
        report_lines.append('2. **启用编译器安全选项**')
        report_lines.append('   - Stack Canary: `-fstack-protector-all`')
        report_lines.append('   - FORTIFY_SOURCE: `-D_FORTIFY_SOURCE=2`')
        report_lines.append('   - PIE: `-fPIE -pie`')
        report_lines.append('   - RELRO: `-Wl,-z,relro,-z,now`')
        report_lines.append('')
        report_lines.append('3. **实施安全开发流程**')
        report_lines.append('   - 定期进行安全代码审查')
        report_lines.append('   - 使用静态分析工具')
        report_lines.append('   - 实施动态测试（fuzzing）')
        report_lines.append('')

        report_content = '\\n'.join(report_lines)

    else:
        # 纯文本格式报告
        report_lines = []
        report_lines.append('=' * 60)
        report_lines.append('安全分析报告')
        report_lines.append('=' * 60)
        report_lines.append(f'目标程序: {binary}')
        report_lines.append(f'文件大小: {report_data["file_size"]} bytes')
        report_lines.append(f'分析时间: {report_data["timestamp"]}')
        report_lines.append('')

        report_lines.append('二进制安全特性:')
        report_lines.append('-' * 30)
        report_lines.append(security_check)
        report_lines.append('')

        report_lines.append('危险函数分析:')
        report_lines.append('-' * 30)
        report_lines.append(dangerous_funcs)
        report_lines.append('')

        if analysis_results:
            report_lines.append('详细分析结果:')
            report_lines.append('-' * 30)
            for section, content in analysis_results.items():
                report_lines.append(f'{section}:')
                if isinstance(content, str):
                    report_lines.append(content)
                else:
                    report_lines.append(str(content))
                report_lines.append('')

        report_content = '\\n'.join(report_lines)

    # 保存到文件（如果指定）
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return f'安全分析报告已生成: {output_file}'
        except Exception as e:
            return f'报告保存失败: {str(e)}\\n\\n{report_content}'

    return report_content


def create_analysis_workspace(base_dir: str = '/workspace/security') -> str:
    """创建安全分析工作空间

    Args:
        base_dir: 基础目录路径

    Returns:
        工作空间创建结果
    """
    directories = [
        'fuzzing/input',
        'fuzzing/output',
        'crashes',
        'symbolic',
        'reports',
        'tools',
        'samples',
    ]

    results = []
    results.append('=== 创建安全分析工作空间 ===')
    results.append(f'基础目录: {base_dir}')

    try:
        for directory in directories:
            full_path = os.path.join(base_dir, directory)
            os.makedirs(full_path, exist_ok=True)
            results.append(f'✓ 创建目录: {full_path}')

        # 创建README文件
        readme_content = """# 安全分析工作空间

这个目录用于组织安全分析活动：

- fuzzing/: AFL++模糊测试相关文件
  - input/: 输入种子
  - output/: fuzzing输出结果
- crashes/: 崩溃样本和分析结果
- symbolic/: KLEE符号执行输出
- reports/: 生成的安全分析报告
- tools/: 辅助工具和脚本
- samples/: 目标程序和测试样本

使用SecurityAgent进行分析时，建议将所有输出组织到相应的子目录中。
"""

        readme_path = os.path.join(base_dir, 'README.md')
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        results.append(f'✓ 创建说明文件: {readme_path}')

        results.append('\\n工作空间创建完成，可以开始安全分析工作')

    except Exception as e:
        results.append(f'✗ 工作空间创建失败: {str(e)}')

    return '\\n'.join(results)


# 导出的公共函数
__all__ = [
    'check_binary_security',
    'extract_functions',
    'find_dangerous_functions',
    'generate_security_report',
    'create_analysis_workspace',
]
