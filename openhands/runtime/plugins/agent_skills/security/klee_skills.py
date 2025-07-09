"""KLEE Skills - KLEE符号执行工具封装

提供KLEE符号执行的Python接口，用于深度路径分析、约束求解和测试用例生成。
所有功能都专注于防御性安全分析。
"""

import glob
import os
import subprocess
import time
from typing import Optional, Union


def compile_for_klee(
    source_files: Union[str, list[str]],
    output: Optional[str] = None,
    include_dirs: Optional[list[str]] = None,
    defines: Optional[list[str]] = None,
    optimization_level: str = '0',
) -> str:
    """编译源代码为KLEE可用的LLVM bitcode

    Args:
        source_files: 源文件路径（单个文件或文件列表）
        output: 输出bitcode文件路径（可选）
        include_dirs: 包含目录列表
        defines: 预处理器定义列表
        optimization_level: 优化级别（0, 1, 2, 3, s, z）

    Returns:
        编译结果信息
    """
    # 处理输入参数
    if isinstance(source_files, str):
        source_files = [source_files]

    # 检查源文件存在性
    for source in source_files:
        if not os.path.exists(source):
            return f'错误：源文件 {source} 不存在'

    # 确定输出文件名
    if output is None:
        if len(source_files) == 1:
            base_name = os.path.splitext(source_files[0])[0]
            output = f'{base_name}.bc'
        else:
            output = 'combined.bc'

    # 构建编译命令
    cmd_parts = ['clang']

    # 添加LLVM bitcode生成选项
    cmd_parts.extend(
        [
            '-emit-llvm',
            '-c',
            '-g',  # 包含调试信息
            f'-O{optimization_level}',
            '-Xclang',
            '-disable-O0-optnone',  # 确保KLEE可以分析
        ]
    )

    # 添加包含目录
    if include_dirs:
        for include_dir in include_dirs:
            cmd_parts.extend(['-I', include_dir])

    # 添加预处理器定义
    if defines:
        for define in defines:
            cmd_parts.extend(['-D', define])

    # 添加源文件和输出
    cmd_parts.extend(source_files)
    cmd_parts.extend(['-o', output])

    try:
        # 执行编译
        cmd_str = ' '.join(cmd_parts)
        result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            # 验证输出文件
            if os.path.exists(output):
                file_size = os.path.getsize(output)
                return (
                    f'成功编译为LLVM bitcode:\\n'
                    f'输出文件: {output}\\n'
                    f'文件大小: {file_size} bytes\\n'
                    f'编译命令: {cmd_str}'
                )
            else:
                return f'编译命令执行成功但未找到输出文件: {output}'
        else:
            return (
                f'编译失败:\\n'
                f'命令: {cmd_str}\\n'
                f'错误输出:\\n{result.stderr}\\n'
                f'标准输出:\\n{result.stdout}'
            )

    except Exception as e:
        return f'编译过程发生异常: {str(e)}'


def run_symbolic_execution(
    bitcode_file: str,
    max_time: int = 3600,
    max_memory: int = 2000,
    max_instruction_time: int = 30,
    max_solver_time: int = 30,
    search_strategy: str = 'random-path',
    output_dir: Optional[str] = None,
    symbolic_args: Optional[dict] = None,
) -> str:
    """运行KLEE符号执行

    Args:
        bitcode_file: LLVM bitcode文件路径
        max_time: 最大执行时间（秒）
        max_memory: 最大内存使用（MB）
        max_instruction_time: 单指令最大执行时间（秒）
        max_solver_time: 约束求解器最大时间（秒）
        search_strategy: 搜索策略（random-path, dfs, bfs等）
        output_dir: 输出目录名（可选）
        symbolic_args: 符号化参数配置

    Returns:
        KLEE执行状态信息
    """
    if not os.path.exists(bitcode_file):
        return f'错误：bitcode文件 {bitcode_file} 不存在'

    # 确定输出目录
    if output_dir is None:
        base_name = os.path.basename(bitcode_file).split('.')[0]
        output_dir = f'klee-out-{base_name}'

    # 如果输出目录已存在，创建新的编号目录
    counter = 1
    original_output_dir = output_dir
    while os.path.exists(output_dir):
        output_dir = f'{original_output_dir}-{counter}'
        counter += 1

    # 构建KLEE命令
    cmd_parts = ['klee']

    # 添加基本参数
    cmd_parts.extend(
        [
            f'--max-time={max_time}',
            f'--max-memory={max_memory}',
            f'--max-instruction-time={max_instruction_time}',
            f'--max-solver-time={max_solver_time}',
            f'--search={search_strategy}',
            f'--output-dir={output_dir}',
        ]
    )

    # 添加有用的分析选项
    cmd_parts.extend(
        [
            '--write-cvcs',  # 生成约束条件
            '--write-cov',  # 生成覆盖率信息
            '--write-test-info',  # 生成测试信息
            '--write-paths',  # 生成路径信息
            '--use-forked-solver',  # 使用fork的求解器进程
            '--max-static-fork-pct=1',  # 允许静态fork
            '--max-static-solve-pct=1',  # 允许静态求解
            '--max-static-cpfork-pct=1',  # 允许静态cp fork
        ]
    )

    # 添加符号化参数配置
    if symbolic_args:
        if 'argc' in symbolic_args:
            cmd_parts.extend(['--sym-args', str(symbolic_args['argc']), '10', '10'])
        if 'files' in symbolic_args:
            cmd_parts.extend(['--sym-files', str(symbolic_args['files']), '1024'])
        if 'stdin' in symbolic_args:
            cmd_parts.extend(['--sym-stdin', str(symbolic_args['stdin'])])

    # 添加bitcode文件
    cmd_parts.append(bitcode_file)

    try:
        # 创建执行日志
        log_file = f'{output_dir}.log'
        cmd_str = ' '.join(cmd_parts)

        # 启动KLEE（后台运行）
        with open(log_file, 'w') as log:
            process = subprocess.Popen(
                cmd_str, shell=True, stdout=log, stderr=subprocess.STDOUT, text=True
            )

        # 等待一段时间检查初始状态
        time.sleep(3)

        if process.poll() is None:
            # 进程仍在运行
            return (
                f'KLEE符号执行已启动:\\n'
                f'输出目录: {output_dir}\\n'
                f'执行日志: {log_file}\\n'
                f'最大运行时间: {max_time} 秒\\n'
                f'内存限制: {max_memory} MB\\n'
                f'命令: {cmd_str}\\n\\n'
                f"使用 analyze_klee_results('{output_dir}') 分析结果"
            )
        else:
            # 进程已结束，可能是错误
            with open(log_file, 'r') as log:
                log_content = log.read()
            return (
                f'KLEE执行可能遇到问题:\\n'
                f'输出目录: {output_dir}\\n'
                f'执行日志:\\n{log_content}'
            )

    except Exception as e:
        return f'启动KLEE失败: {str(e)}'


def analyze_klee_results(output_dir: str, detailed: bool = True) -> str:
    """分析KLEE执行结果

    Args:
        output_dir: KLEE输出目录
        detailed: 是否显示详细信息

    Returns:
        分析结果报告
    """
    if not os.path.exists(output_dir):
        return f'错误：KLEE输出目录 {output_dir} 不存在'

    results = []
    results.append('=== KLEE执行结果分析 ===')
    results.append(f'输出目录: {output_dir}')
    results.append('')

    # 统计测试用例
    ktest_files = glob.glob(os.path.join(output_dir, '*.ktest'))
    results.append(f'生成测试用例数: {len(ktest_files)}')

    # 统计错误
    error_files = glob.glob(os.path.join(output_dir, '*.err'))
    results.append(f'发现错误数: {len(error_files)}')

    # 统计断言失败
    assert_files = glob.glob(os.path.join(output_dir, '*.assert.err'))
    results.append(f'断言失败数: {len(assert_files)}')

    # 统计路径探索
    path_files = glob.glob(os.path.join(output_dir, '*.path'))
    results.append(f'探索路径数: {len(path_files)}')

    # 读取统计信息
    info_file = os.path.join(output_dir, 'info')
    if os.path.exists(info_file):
        results.append('\\n=== 执行统计信息 ===')
        with open(info_file, 'r') as f:
            info_content = f.read()
            results.append(info_content)

    # 读取运行统计
    run_stats_file = os.path.join(output_dir, 'run.stats')
    if os.path.exists(run_stats_file):
        results.append('\\n=== 运行时统计 ===')
        try:
            with open(run_stats_file, 'r') as f:
                stats_content = f.read()
                # 解析关键统计信息
                lines = stats_content.strip().split('\\n')
                if len(lines) > 1:
                    headers = lines[0].split(',')
                    values = lines[-1].split(',')  # 取最后一行（最终统计）

                    # 显示关键指标
                    key_metrics = [
                        'Instructions',
                        'FullBranches',
                        'PartialBranches',
                        'NumBranches',
                        'UserTime',
                        'NumStates',
                    ]

                    for metric in key_metrics:
                        if metric in headers:
                            idx = headers.index(metric)
                            if idx < len(values):
                                results.append(f'{metric}: {values[idx]}')
        except Exception as e:
            results.append(f'读取运行统计失败: {str(e)}')

    # 分析错误类型
    if error_files and detailed:
        results.append('\\n=== 错误分析 ===')
        error_types = {}

        for err_file in error_files[:10]:  # 只分析前10个错误
            try:
                with open(err_file, 'r') as f:
                    error_content = f.read()

                # 分类错误类型
                if 'division by zero' in error_content:
                    error_type = '除零错误'
                elif 'memory error' in error_content:
                    error_type = '内存错误'
                elif 'buffer overflow' in error_content:
                    error_type = '缓冲区溢出'
                elif 'null pointer' in error_content:
                    error_type = '空指针访问'
                elif 'out of bounds' in error_content:
                    error_type = '数组越界'
                else:
                    error_type = '其他错误'

                if error_type not in error_types:
                    error_types[error_type] = []
                error_types[error_type].append(os.path.basename(err_file))
            except Exception:
                continue

        for error_type, files in error_types.items():
            results.append(f'{error_type}: {len(files)} 个')
            if detailed and len(files) <= 3:
                for file in files:
                    results.append(f'  - {file}')

    # 覆盖率信息
    cov_file = os.path.join(output_dir, 'run.istats')
    if os.path.exists(cov_file):
        results.append('\\n=== 代码覆盖率 ===')
        try:
            with open(cov_file, 'r') as f:
                lines = f.readlines()
                if len(lines) > 1:
                    # 简单统计覆盖的指令数
                    covered_instructions = len(
                        [line for line in lines[1:] if line.strip()]
                    )
                    results.append(f'覆盖指令数: {covered_instructions}')
        except Exception:
            results.append('覆盖率信息读取失败')

    # 提供后续建议
    results.append('\\n=== 后续分析建议 ===')
    if len(error_files) > 0:
        results.append('• 使用 generate_test_cases() 生成具体的错误触发输入')
        results.append('• 分析错误文件以了解具体的漏洞类型')
    if len(ktest_files) > 0:
        results.append('• 使用生成的测试用例进行回归测试')
        results.append('• 分析高覆盖率路径的测试用例')
    if len(assert_files) > 0:
        results.append('• 检查断言失败，可能表明逻辑错误')

    return '\\n'.join(results)


def generate_test_cases(
    output_dir: str, max_cases: int = 20, save_to_dir: Optional[str] = None
) -> str:
    """从KLEE结果生成具体的测试用例

    Args:
        output_dir: KLEE输出目录
        max_cases: 最大生成用例数
        save_to_dir: 保存测试用例的目录（可选）

    Returns:
        测试用例生成结果
    """
    if not os.path.exists(output_dir):
        return f'错误：KLEE输出目录 {output_dir} 不存在'

    # 查找测试文件
    ktest_files = glob.glob(os.path.join(output_dir, '*.ktest'))

    if not ktest_files:
        return f'在目录 {output_dir} 中未找到 .ktest 文件'

    # 限制处理数量
    ktest_files = sorted(ktest_files)[:max_cases]

    results = []
    results.append('=== KLEE测试用例生成 ===')
    results.append(f'源目录: {output_dir}')
    results.append(f'处理文件数: {len(ktest_files)}')

    if save_to_dir:
        os.makedirs(save_to_dir, exist_ok=True)
        results.append(f'保存目录: {save_to_dir}')

    results.append('')

    successful_cases = 0

    for i, ktest_file in enumerate(ktest_files):
        try:
            # 使用ktest-tool提取测试数据
            cmd = f'ktest-tool {ktest_file}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                successful_cases += 1

                test_name = os.path.basename(ktest_file)
                results.append(f'测试用例 {i + 1}: {test_name}')

                # 解析ktest-tool输出
                output_lines = result.stdout.split('\\n')
                objects = []
                current_object = None

                for line in output_lines:
                    line = line.strip()
                    if line.startswith('object'):
                        if current_object:
                            objects.append(current_object)
                        current_object = {'name': '', 'size': 0, 'data': ''}
                    elif line.startswith('name:') and current_object is not None:
                        current_object['name'] = (
                            line.split(':', 1)[1].strip().strip('"')
                        )
                    elif line.startswith('size:') and current_object is not None:
                        try:
                            current_object['size'] = int(line.split(':', 1)[1].strip())
                        except (ValueError, IndexError):
                            pass
                    elif line.startswith('data:') and current_object is not None:
                        current_object['data'] = line.split(':', 1)[1].strip()

                if current_object:
                    objects.append(current_object)

                # 显示对象信息
                for obj in objects:
                    if obj['name'] and obj['size'] > 0:
                        results.append(
                            f'  对象: {obj["name"]}, 大小: {obj["size"]} bytes'
                        )
                        if obj['data']:
                            # 显示数据的可读形式
                            data_preview = obj['data'][:50]
                            if len(obj['data']) > 50:
                                data_preview += '...'
                            results.append(f'  数据: {data_preview}')

                # 保存测试用例到文件
                if save_to_dir:
                    case_file = os.path.join(save_to_dir, f'testcase_{i + 1:03d}.txt')
                    with open(case_file, 'w') as f:
                        f.write(f'# 从 {test_name} 生成\\n')
                        f.write(result.stdout)

                    # 如果是简单的输入数据，也创建二进制文件
                    if (
                        objects
                        and len(objects) == 1
                        and objects[0]['name'] in ['stdin', 'arg']
                    ):
                        binary_file = os.path.join(
                            save_to_dir, f'input_{i + 1:03d}.bin'
                        )
                        try:
                            # 简单的十六进制转换（ktest-tool输出格式）
                            hex_data = (
                                objects[0]['data'].replace('\\\\x', '').replace(' ', '')
                            )
                            if all(c in '0123456789abcdefABCDEF' for c in hex_data):
                                binary_data = bytes.fromhex(hex_data)
                                with open(binary_file, 'wb') as bf:
                                    bf.write(binary_data)
                                results.append(
                                    f'  已保存二进制输入: {os.path.basename(binary_file)}'
                                )
                        except Exception:
                            pass  # 如果转换失败，跳过二进制文件生成

                results.append('')

            else:
                results.append(
                    f'测试用例 {i + 1}: 解析失败 - {os.path.basename(ktest_file)}'
                )
                if result.stderr:
                    results.append(f'  错误: {result.stderr.strip()}')
                results.append('')

        except Exception as e:
            results.append(f'测试用例 {i + 1}: 处理异常 - {str(e)}')
            results.append('')

    # 生成摘要
    results.append('=== 生成摘要 ===')
    results.append(f'成功生成: {successful_cases}/{len(ktest_files)} 个测试用例')

    if save_to_dir and successful_cases > 0:
        results.append(f'测试用例已保存到: {save_to_dir}')
        results.append('可以使用这些测试用例进行回归测试或进一步的漏洞分析')

    return '\\n'.join(results)


def check_klee_status(output_dir: str) -> str:
    """检查KLEE执行状态

    Args:
        output_dir: KLEE输出目录

    Returns:
        执行状态信息
    """
    if not os.path.exists(output_dir):
        return f'KLEE输出目录 {output_dir} 不存在，可能尚未开始执行'

    status_info = []
    status_info.append('=== KLEE执行状态 ===')
    status_info.append(f'输出目录: {output_dir}')

    # 检查是否有进程在运行
    try:
        result = subprocess.run(
            'pgrep -f klee', shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            pids = result.stdout.strip().split('\\n')
            status_info.append(f'运行状态: KLEE进程运行中 (PID: {", ".join(pids)})')
        else:
            status_info.append('运行状态: 未发现运行中的KLEE进程')
    except (subprocess.SubprocessError, OSError):
        status_info.append('运行状态: 无法检查进程状态')

    # 检查输出文件
    ktest_count = len(glob.glob(os.path.join(output_dir, '*.ktest')))
    error_count = len(glob.glob(os.path.join(output_dir, '*.err')))

    status_info.append(f'当前测试用例数: {ktest_count}')
    status_info.append(f'当前错误数: {error_count}')

    # 检查最近更新时间
    try:
        latest_file = None
        latest_time = 0

        for file_pattern in ['*.ktest', '*.err', 'run.stats']:
            files = glob.glob(os.path.join(output_dir, file_pattern))
            for file in files:
                mtime = os.path.getmtime(file)
                if mtime > latest_time:
                    latest_time = mtime
                    latest_file = file

        if latest_file:
            import datetime

            last_update = datetime.datetime.fromtimestamp(latest_time)
            status_info.append(f'最近更新: {last_update.strftime("%Y-%m-%d %H:%M:%S")}')
            status_info.append(f'最新文件: {os.path.basename(latest_file)}')
    except (OSError, ValueError):
        status_info.append('无法获取文件更新时间')

    return '\\n'.join(status_info)


# 导出的公共函数
__all__ = [
    'compile_for_klee',
    'run_symbolic_execution',
    'analyze_klee_results',
    'generate_test_cases',
    'check_klee_status',
]
