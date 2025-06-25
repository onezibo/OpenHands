"""AFL++ Skills - AFL++模糊测试工具封装

提供AFL++的Python接口，支持启动fuzzing、状态监控、崩溃收集等功能。
所有功能都专注于防御性安全分析。
"""

import os
import subprocess
import json
import time
from typing import Dict, List, Optional, Union


def start_fuzzing(
    binary: str, 
    input_dir: str, 
    output_dir: str, 
    timeout: int = 3600, 
    cores: int = 1,
    memory_limit: str = "none",
    dictionary: Optional[str] = None,
    qemu_mode: bool = False
) -> str:
    """启动AFL++模糊测试
    
    Args:
        binary: 目标二进制文件路径
        input_dir: 输入种子目录
        output_dir: 输出目录
        timeout: 超时时间（秒）
        cores: 使用的CPU核心数
        memory_limit: 内存限制（MB或"none"）
        dictionary: 字典文件路径（可选）
        qemu_mode: 是否使用QEMU模式（用于无源码二进制）
    
    Returns:
        执行结果或错误信息
    """
    # 检查前置条件
    if not os.path.exists(binary):
        return f"错误：二进制文件 {binary} 不存在"
    
    if not os.path.exists(input_dir):
        return f"错误：输入目录 {input_dir} 不存在"
    
    # 检查输入目录是否为空
    if not os.listdir(input_dir):
        return f"错误：输入目录 {input_dir} 为空，请提供至少一个种子文件"
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 构建AFL++基础命令
    cmd_parts = [f"timeout {timeout}", "afl-fuzz"]
    
    # 添加输入输出参数
    cmd_parts.extend(["-i", input_dir, "-o", output_dir])
    
    # 添加内存限制
    if memory_limit != "none":
        cmd_parts.extend(["-m", str(memory_limit)])
    
    # 添加字典支持
    if dictionary and os.path.exists(dictionary):
        cmd_parts.extend(["-x", dictionary])
    
    # 添加QEMU模式支持
    if qemu_mode:
        cmd_parts.append("-Q")
    
    try:
        if cores > 1:
            # 多核并行fuzzing
            results = []
            
            # 主fuzzer
            master_cmd = cmd_parts + ["-M", "fuzzer01", "--", binary, "@@"]
            master_cmd_str = " ".join(master_cmd)
            
            # 启动主fuzzer（后台运行）
            with open(f"{output_dir}/master.log", "w") as log_file:
                subprocess.Popen(
                    master_cmd_str, 
                    shell=True, 
                    stdout=log_file, 
                    stderr=subprocess.STDOUT
                )
            results.append(f"主fuzzer已启动: {master_cmd_str}")
            
            # 等待主fuzzer初始化
            time.sleep(2)
            
            # 启动从fuzzer
            for i in range(2, cores + 1):
                slave_cmd = cmd_parts + ["-S", f"fuzzer{i:02d}", "--", binary, "@@"]
                slave_cmd_str = " ".join(slave_cmd)
                
                with open(f"{output_dir}/slave_{i:02d}.log", "w") as log_file:
                    subprocess.Popen(
                        slave_cmd_str, 
                        shell=True, 
                        stdout=log_file, 
                        stderr=subprocess.STDOUT
                    )
                results.append(f"从fuzzer{i:02d}已启动: {slave_cmd_str}")
            
            return f"启动了 {cores} 个AFL++实例进行并行fuzzing:\\n" + "\\n".join(results)
        
        else:
            # 单核fuzzing
            single_cmd = cmd_parts + ["--", binary, "@@"]
            single_cmd_str = " ".join(single_cmd)
            
            with open(f"{output_dir}/fuzzing.log", "w") as log_file:
                subprocess.Popen(
                    single_cmd_str, 
                    shell=True, 
                    stdout=log_file, 
                    stderr=subprocess.STDOUT
                )
            
            return f"AFL++已在后台启动:\\n命令: {single_cmd_str}\\n日志: {output_dir}/fuzzing.log"
    
    except Exception as e:
        return f"启动AFL++失败: {str(e)}"


def check_fuzzing_status(output_dir: str) -> str:
    """检查fuzzing状态
    
    Args:
        output_dir: AFL++输出目录
        
    Returns:
        fuzzing状态信息
    """
    if not os.path.exists(output_dir):
        return f"错误：输出目录 {output_dir} 不存在"
    
    status_info = []
    found_stats = False
    
    # 检查单核模式的统计文件
    single_stats = os.path.join(output_dir, "fuzzer_stats")
    if os.path.exists(single_stats):
        status_info.append("=== 单核Fuzzing状态 ===")
        with open(single_stats, 'r') as f:
            content = f.read()
            status_info.append(content)
        found_stats = True
    
    # 检查多核模式的统计文件
    for item in os.listdir(output_dir):
        item_path = os.path.join(output_dir, item)
        if os.path.isdir(item_path) and item.startswith("fuzzer"):
            fuzzer_stats = os.path.join(item_path, "fuzzer_stats")
            if os.path.exists(fuzzer_stats):
                status_info.append(f"\\n=== {item} 状态 ===")
                with open(fuzzer_stats, 'r') as f:
                    content = f.read()
                    status_info.append(content)
                found_stats = True
    
    if not found_stats:
        return "未找到fuzzing统计信息，可能fuzzing尚未开始或目录结构不正确"
    
    return "\\n".join(status_info)


def collect_crashes(output_dir: str, analyze_limit: int = 50) -> str:
    """收集并分类崩溃样本
    
    Args:
        output_dir: AFL++输出目录
        analyze_limit: 分析的最大崩溃数量
        
    Returns:
        崩溃收集结果
    """
    if not os.path.exists(output_dir):
        return f"错误：输出目录 {output_dir} 不存在"
    
    crashes = []
    crash_dirs = []
    
    # 收集所有可能的崩溃目录
    # 单核模式
    single_crash_dir = os.path.join(output_dir, "crashes")
    if os.path.exists(single_crash_dir):
        crash_dirs.append(("default", single_crash_dir))
    
    # 多核模式
    for item in os.listdir(output_dir):
        item_path = os.path.join(output_dir, item)
        if os.path.isdir(item_path) and item.startswith("fuzzer"):
            crash_dir = os.path.join(item_path, "crashes")
            if os.path.exists(crash_dir):
                crash_dirs.append((item, crash_dir))
    
    # 收集崩溃文件
    for fuzzer_name, crash_dir in crash_dirs:
        try:
            for crash_file in os.listdir(crash_dir):
                if crash_file.startswith("id:") and not crash_file.endswith(".analysis"):
                    crash_path = os.path.join(crash_dir, crash_file)
                    if os.path.isfile(crash_path):
                        crashes.append({
                            'file': crash_path,
                            'size': os.path.getsize(crash_path),
                            'fuzzer': fuzzer_name,
                            'name': crash_file
                        })
        except PermissionError:
            continue
    
    if not crashes:
        return "未发现任何崩溃样本"
    
    # 按大小排序，有助于分析
    crashes.sort(key=lambda x: x['size'])
    
    # 生成摘要
    summary = [f"发现 {len(crashes)} 个崩溃样本"]
    
    # 按fuzzer分组统计
    fuzzer_stats = {}
    for crash in crashes:
        fuzzer = crash['fuzzer']
        if fuzzer not in fuzzer_stats:
            fuzzer_stats[fuzzer] = 0
        fuzzer_stats[fuzzer] += 1
    
    summary.append("\\n按fuzzer分组:")
    for fuzzer, count in fuzzer_stats.items():
        summary.append(f"  {fuzzer}: {count} 个崩溃")
    
    # 显示详细信息（限制数量）
    summary.append(f"\\n前 {min(analyze_limit, len(crashes))} 个崩溃详情:")
    for i, crash in enumerate(crashes[:analyze_limit]):
        summary.append(f"{i+1:3d}. {crash['name']} ({crash['size']} bytes) [{crash['fuzzer']}]")
        summary.append(f"     路径: {crash['file']}")
    
    if len(crashes) > analyze_limit:
        summary.append(f"\\n... 还有 {len(crashes) - analyze_limit} 个崩溃样本未显示")
        summary.append(f"所有崩溃文件保存在相应的crashes目录中")
    
    return "\\n".join(summary)


def minimize_corpus(input_dir: str, output_dir: str, binary: str, timeout: int = 300) -> str:
    """最小化测试语料库
    
    Args:
        input_dir: 原始语料库目录
        output_dir: 最小化后的输出目录
        binary: 目标二进制文件
        timeout: 超时时间
        
    Returns:
        最小化结果
    """
    if not os.path.exists(input_dir):
        return f"错误：输入目录 {input_dir} 不存在"
    
    if not os.path.exists(binary):
        return f"错误：二进制文件 {binary} 不存在"
    
    os.makedirs(output_dir, exist_ok=True)
    
    cmd = f"timeout {timeout} afl-cmin -i {input_dir} -o {output_dir} -- {binary} @@"
    
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=timeout + 10  # 稍微延长超时时间
        )
        
        # 统计结果
        input_count = len([f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))])
        output_count = 0
        if os.path.exists(output_dir):
            output_count = len([f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))])
        
        return (f"语料库最小化完成:\\n"
                f"原始文件数: {input_count}\\n"
                f"最小化后: {output_count}\\n"
                f"压缩率: {(1 - output_count/max(input_count, 1)) * 100:.1f}%\\n\\n"
                f"afl-cmin输出:\\n{result.stdout}\\n"
                f"错误信息:\\n{result.stderr}")
        
    except subprocess.TimeoutExpired:
        return f"语料库最小化超时（{timeout}秒），可能语料库过大或目标程序响应缓慢"
    except Exception as e:
        return f"最小化失败: {str(e)}"


def triage_crashes(output_dir: str, binary: str, max_crashes: int = 20) -> str:
    """对崩溃进行初步分类
    
    Args:
        output_dir: AFL++输出目录
        binary: 目标二进制文件
        max_crashes: 最大分析崩溃数量
        
    Returns:
        崩溃分类结果
    """
    if not os.path.exists(output_dir):
        return f"错误：输出目录 {output_dir} 不存在"
    
    if not os.path.exists(binary):
        return f"错误：二进制文件 {binary} 不存在"
    
    # 首先收集崩溃
    crash_collection = collect_crashes(output_dir, max_crashes)
    if "未发现任何崩溃样本" in crash_collection:
        return crash_collection
    
    # 尝试使用afl-collect进行分类（如果可用）
    collect_cmd = f"afl-collect -r {output_dir} -- {binary} @@"
    
    try:
        # 检查afl-collect是否可用
        check_cmd = "which afl-collect"
        check_result = subprocess.run(check_cmd, shell=True, capture_output=True)
        
        if check_result.returncode == 0:
            result = subprocess.run(
                collect_cmd, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return (f"使用afl-collect进行崩溃分类:\\n\\n"
                        f"{result.stdout}\\n\\n"
                        f"原始收集信息:\\n{crash_collection}")
            else:
                return (f"afl-collect执行失败，使用基础分类:\\n"
                        f"错误: {result.stderr}\\n\\n"
                        f"基础崩溃信息:\\n{crash_collection}")
        else:
            return (f"afl-collect工具不可用，提供基础崩溃信息:\\n\\n"
                    f"{crash_collection}\\n\\n"
                    f"建议: 安装afl-collect工具进行高级崩溃分类，或使用GDB进行手动分析")
    
    except subprocess.TimeoutExpired:
        return (f"崩溃分类超时，提供基础信息:\\n\\n"
                f"{crash_collection}\\n\\n"
                f"建议: 减少崩溃数量或使用GDB进行手动分析")
    except Exception as e:
        return (f"崩溃分类失败: {str(e)}\\n\\n"
                f"基础崩溃信息:\\n{crash_collection}")


def stop_fuzzing(output_dir: str) -> str:
    """停止正在运行的fuzzing任务
    
    Args:
        output_dir: AFL++输出目录
        
    Returns:
        停止操作结果
    """
    try:
        # 查找afl-fuzz进程
        result = subprocess.run(
            "pgrep -f afl-fuzz", 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        if result.returncode == 0:
            pids = result.stdout.strip().split('\\n')
            killed_count = 0
            
            for pid in pids:
                if pid.strip():
                    try:
                        subprocess.run(f"kill {pid}", shell=True, check=True)
                        killed_count += 1
                    except subprocess.CalledProcessError:
                        pass
            
            return f"已停止 {killed_count} 个AFL++进程"
        else:
            return "未发现正在运行的AFL++进程"
    
    except Exception as e:
        return f"停止fuzzing失败: {str(e)}"


# 导出的公共函数
__all__ = [
    'start_fuzzing',
    'check_fuzzing_status', 
    'collect_crashes',
    'minimize_corpus',
    'triage_crashes',
    'stop_fuzzing'
]