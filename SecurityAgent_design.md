# SecurityAgent设计方案 - 详细实施版

## 一、设计理念与原则

本方案基于"最小修改OpenHands"的核心原则，通过巧妙利用OpenHands现有能力来集成安全分析工具，而非重构系统架构。

### 核心设计原则
1. **保持架构稳定**：不改变OpenHands核心架构，仅添加必要组件
2. **命令行优先**：所有安全工具通过标准命令行接口调用
3. **文件系统交互**：利用文件系统进行工具间数据传递
4. **智能决策**：依靠LLM的推理能力处理复杂分析逻辑
5. **渐进式实现**：从简单功能开始，逐步增强能力

## 二、架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                    SecurityAgent                         │
│              (继承自CodeActAgent)                        │
├─────────────────────────────────────────────────────────┤
│                  Agent Skills                           │
│    ┌──────────┐ ┌──────────┐ ┌──────────────┐        │
│    │ AFL++    │ │   GDB    │ │    KLEE      │        │
│    │ Skills   │ │ Skills   │ │   Skills     │        │
│    └──────────┘ └──────────┘ └──────────────┘        │
├─────────────────────────────────────────────────────────┤
│                 Bash Execution Layer                    │
│         (利用OpenHands现有的命令执行能力)                 │
├─────────────────────────────────────────────────────────┤
│              Docker Runtime Environment                 │
│         (包含AFL++、GDB、KLEE等工具)                    │
└─────────────────────────────────────────────────────────┘
```

### 2.2 关键组件说明

#### 1. SecurityAgent（最小化实现）
```python
# 位置：openhands/agenthub/security_agent/security_agent.py

from openhands.controller.agent import Agent
from openhands.agenthub.codeact_agent.codeact_agent import CodeActAgent
from openhands.core.config import AgentConfig
from openhands.llm.llm import LLM

class SecurityAgent(CodeActAgent):
    """安全分析代理，继承CodeActAgent的所有能力"""

    VERSION = '1.0'

    def __init__(self, llm: LLM, config: AgentConfig):
        super().__init__(llm, config)
        # 仅添加安全分析特定的配置
        self.security_prompt = self._load_security_prompt()

    def _load_security_prompt(self):
        """加载安全分析专用提示词"""
        return """
        你是一个专业的安全分析助手，精通使用AFL++、GDB和KLEE等工具。
        你可以通过bash命令直接调用这些工具：
        - AFL++: afl-fuzz, afl-showmap, afl-tmin, afl-cmin等
        - GDB: gdb -batch模式进行崩溃分析
        - KLEE: 符号执行分析
        - 辅助工具: checksec, file, strings, objdump等

        分析流程：
        1. 先理解目标程序（file, checksec, strings）
        2. 选择合适的分析方法（fuzzing/符号执行/手工分析）
        3. 执行分析并解释结果
        4. 提供详细的安全建议和修复方案

        注意事项：
        - 使用timeout命令限制长时间运行的任务
        - 定期检查分析进度并调整策略
        - 保存重要的中间结果
        """

    @property
    def prompt_manager(self):
        """重写prompt管理器以包含安全分析prompt"""
        pm = super().prompt_manager
        # 在系统提示词中添加安全分析相关内容
        pm.system_prompt = pm.system_prompt + "\n\n" + self.security_prompt
        return pm

# 注册SecurityAgent
Agent.register("SecurityAgent", SecurityAgent)
```

#### 2. Agent Skills（详细实现）
```python
# 位置：openhands/runtime/plugins/agent_skills/security/__init__.py

from .afl_skills import (
    start_fuzzing,
    check_fuzzing_status,
    collect_crashes,
    minimize_corpus,
    triage_crashes
)
from .gdb_skills import (
    analyze_crash,
    batch_analyze_crashes,
    extract_crash_info,
    check_exploitability
)
from .klee_skills import (
    compile_for_klee,
    run_symbolic_execution,
    analyze_klee_results,
    generate_test_cases
)
from .analysis_skills import (
    check_binary_security,
    extract_functions,
    find_dangerous_functions,
    generate_security_report
)

__all__ = [
    'start_fuzzing', 'check_fuzzing_status', 'collect_crashes',
    'minimize_corpus', 'triage_crashes',
    'analyze_crash', 'batch_analyze_crashes', 'extract_crash_info',
    'check_exploitability',
    'compile_for_klee', 'run_symbolic_execution', 'analyze_klee_results',
    'generate_test_cases',
    'check_binary_security', 'extract_functions', 'find_dangerous_functions',
    'generate_security_report'
]
```

```python
# 位置：openhands/runtime/plugins/agent_skills/security/afl_skills.py

import os
import subprocess
import json
from typing import Dict, List

def start_fuzzing(binary: str, input_dir: str, output_dir: str,
                  timeout: int = 3600, cores: int = 1) -> str:
    """
    启动AFL++模糊测试

    Args:
        binary: 目标二进制文件路径
        input_dir: 输入种子目录
        output_dir: 输出目录
        timeout: 超时时间（秒）
        cores: 使用的CPU核心数

    Returns:
        执行结果或错误信息
    """
    # 检查前置条件
    if not os.path.exists(binary):
        return f"错误：二进制文件 {binary} 不存在"

    if not os.path.exists(input_dir):
        return f"错误：输入目录 {input_dir} 不存在"

    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)

    # 构建AFL++命令
    cmd = f"timeout {timeout} afl-fuzz -i {input_dir} -o {output_dir}"

    # 多核支持
    if cores > 1:
        # 主fuzzer
        master_cmd = f"{cmd} -M fuzzer01 -- {binary} @@"
        subprocess.Popen(master_cmd, shell=True)

        # 从fuzzer
        for i in range(2, cores + 1):
            slave_cmd = f"{cmd} -S fuzzer{i:02d} -- {binary} @@"
            subprocess.Popen(slave_cmd, shell=True)

        return f"启动了 {cores} 个AFL++实例进行并行fuzzing"
    else:
        cmd = f"{cmd} -- {binary} @@"
        subprocess.Popen(cmd, shell=True)
        return "AFL++已在后台启动"

def check_fuzzing_status(output_dir: str) -> str:
    """检查fuzzing状态"""
    stats_file = os.path.join(output_dir, "fuzzer_stats")

    if not os.path.exists(stats_file):
        # 检查多核模式
        multi_stats = []
        for fuzzer_dir in os.listdir(output_dir):
            fuzzer_stats = os.path.join(output_dir, fuzzer_dir, "fuzzer_stats")
            if os.path.exists(fuzzer_stats):
                with open(fuzzer_stats, 'r') as f:
                    content = f.read()
                    multi_stats.append(f"\n=== {fuzzer_dir} ===\n{content}")

        if multi_stats:
            return "\n".join(multi_stats)
        return "未找到fuzzing统计信息"

    with open(stats_file, 'r') as f:
        return f.read()

def collect_crashes(output_dir: str) -> str:
    """收集并分类崩溃样本"""
    crashes = []
    crash_dirs = []

    # 单核模式
    if os.path.exists(os.path.join(output_dir, "crashes")):
        crash_dirs.append(os.path.join(output_dir, "crashes"))

    # 多核模式
    for item in os.listdir(output_dir):
        item_path = os.path.join(output_dir, item)
        if os.path.isdir(item_path):
            crash_dir = os.path.join(item_path, "crashes")
            if os.path.exists(crash_dir):
                crash_dirs.append(crash_dir)

    for crash_dir in crash_dirs:
        for crash_file in os.listdir(crash_dir):
            if crash_file.startswith("id:"):
                crash_path = os.path.join(crash_dir, crash_file)
                crashes.append({
                    'file': crash_path,
                    'size': os.path.getsize(crash_path),
                    'dir': crash_dir
                })

    summary = f"发现 {len(crashes)} 个崩溃样本\n"
    for i, crash in enumerate(crashes[:10]):  # 只显示前10个
        summary += f"{i+1}. {crash['file']} (大小: {crash['size']} bytes)\n"

    if len(crashes) > 10:
        summary += f"... 还有 {len(crashes) - 10} 个崩溃样本\n"

    return summary

def minimize_corpus(input_dir: str, output_dir: str, binary: str) -> str:
    """最小化测试语料库"""
    cmd = f"afl-cmin -i {input_dir} -o {output_dir} -- {binary} @@"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return f"语料库最小化完成:\n{result.stdout}"
    except Exception as e:
        return f"最小化失败: {str(e)}"

def triage_crashes(output_dir: str, binary: str) -> str:
    """对崩溃进行初步分类"""
    # 使用AFL++的崩溃探索模式
    cmd = f"afl-collect -r {output_dir} -- {binary} @@"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
    except:
        # 如果afl-collect不可用，手动分类
        return "请手动运行GDB分析崩溃样本"
```

```python
# 位置：openhands/runtime/plugins/agent_skills/security/gdb_skills.py

import os
import subprocess
import re
from typing import Dict, List

def analyze_crash(binary: str, crash_file: str, timeout: int = 30) -> str:
    """
    使用GDB分析单个崩溃

    Args:
        binary: 二进制文件路径
        crash_file: 崩溃输入文件
        timeout: 分析超时时间

    Returns:
        GDB分析结果
    """
    gdb_commands = [
        "set pagination off",
        "set confirm off",
        f"file {binary}",
        f"run < {crash_file}",
        "bt",
        "info registers",
        "x/10i $rip",
        "x/20x $rsp",
        "info proc mappings",
        "quit"
    ]

    # 创建GDB脚本
    script_path = "/tmp/gdb_script.txt"
    with open(script_path, 'w') as f:
        f.write('\n'.join(gdb_commands))

    cmd = f"timeout {timeout} gdb -batch -x {script_path} 2>&1"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout + result.stderr

        # 清理临时文件
        os.remove(script_path)

        return output
    except Exception as e:
        return f"GDB分析失败: {str(e)}"

def batch_analyze_crashes(binary: str, crash_dir: str, max_crashes: int = 10) -> str:
    """批量分析崩溃样本"""
    results = []
    crash_files = []

    # 收集崩溃文件
    for root, dirs, files in os.walk(crash_dir):
        for file in files:
            if file.startswith("id:"):
                crash_files.append(os.path.join(root, file))

    # 限制分析数量
    crash_files = crash_files[:max_crashes]

    for i, crash_file in enumerate(crash_files):
        results.append(f"\n{'='*60}")
        results.append(f"分析崩溃 {i+1}/{len(crash_files)}: {crash_file}")
        results.append(f"{'='*60}")

        analysis = analyze_crash(binary, crash_file)
        results.append(analysis)

        # 提取关键信息
        crash_info = extract_crash_info(analysis)
        results.append(f"\n关键信息: {crash_info}")

    return '\n'.join(results)

def extract_crash_info(gdb_output: str) -> Dict[str, str]:
    """从GDB输出中提取关键崩溃信息"""
    info = {
        'signal': 'Unknown',
        'crash_address': 'Unknown',
        'crash_function': 'Unknown',
        'crash_instruction': 'Unknown'
    }

    # 提取信号类型
    signal_match = re.search(r'Program received signal (\w+)', gdb_output)
    if signal_match:
        info['signal'] = signal_match.group(1)

    # 提取崩溃地址
    addr_match = re.search(r'0x[0-9a-fA-F]+ in (\w+)', gdb_output)
    if addr_match:
        info['crash_function'] = addr_match.group(1)

    # 提取崩溃指令
    inst_match = re.search(r'=>\s+0x[0-9a-fA-F]+.*?:\s+(.+?)$', gdb_output, re.MULTILINE)
    if inst_match:
        info['crash_instruction'] = inst_match.group(1)

    return info

def check_exploitability(binary: str, crash_file: str) -> str:
    """检查崩溃的可利用性"""
    # 使用exploitable GDB脚本
    gdb_commands = [
        "set pagination off",
        f"file {binary}",
        f"run < {crash_file}",
        "source /tmp/exploitable.py",  # 假设已安装exploitable
        "exploitable",
        "quit"
    ]

    script_path = "/tmp/exploit_check.txt"
    with open(script_path, 'w') as f:
        f.write('\n'.join(gdb_commands))

    cmd = f"gdb -batch -x {script_path} 2>&1"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout

        # 如果exploitable不可用，进行基础检查
        if "exploitable" not in output:
            output = analyze_crash(binary, crash_file)
            if "SIGSEGV" in output:
                if "stack smashing detected" in output:
                    return "可能存在栈溢出漏洞"
                elif "malloc" in output or "free" in output:
                    return "可能存在堆相关漏洞"
                else:
                    return "内存访问违规，需要进一步分析"

        return output
    except Exception as e:
        return f"可利用性检查失败: {str(e)}"
```

```python
# 位置：openhands/runtime/plugins/agent_skills/security/klee_skills.py

def compile_for_klee(source: str, output: str = None) -> str:
    """编译源代码为KLEE可用的LLVM bitcode"""
    if output is None:
        output = source.rsplit('.', 1)[0] + '.bc'

    # 使用clang编译为LLVM bitcode
    cmd = f"clang -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone {source} -o {output}"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return f"成功编译为bitcode: {output}"
        else:
            return f"编译失败:\n{result.stderr}"
    except Exception as e:
        return f"编译错误: {str(e)}"

def run_symbolic_execution(bitcode: str, max_time: int = 3600,
                          max_memory: int = 2000) -> str:
    """运行KLEE符号执行"""
    output_dir = f"klee-out-{os.path.basename(bitcode)}"

    cmd = f"klee --max-time={max_time} --max-memory={max_memory} " \
          f"--output-dir={output_dir} {bitcode}"

    try:
        # 启动KLEE
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)

        # 等待一段时间获取初始输出
        import time
        time.sleep(5)

        return f"KLEE已启动，输出目录: {output_dir}\n" \
               f"使用 'ls {output_dir}' 查看生成的测试用例"
    except Exception as e:
        return f"KLEE执行失败: {str(e)}"

def analyze_klee_results(output_dir: str) -> str:
    """分析KLEE执行结果"""
    if not os.path.exists(output_dir):
        return f"KLEE输出目录 {output_dir} 不存在"

    results = []

    # 统计测试用例
    test_cases = [f for f in os.listdir(output_dir) if f.endswith('.ktest')]
    results.append(f"生成了 {len(test_cases)} 个测试用例")

    # 检查错误
    errors = [f for f in os.listdir(output_dir) if f.endswith('.err')]
    if errors:
        results.append(f"\n发现 {len(errors)} 个错误:")
        for err in errors[:5]:  # 只显示前5个
            err_path = os.path.join(output_dir, err)
            with open(err_path, 'r') as f:
                content = f.read().strip()
                if content:
                    results.append(f"- {err}: {content[:100]}...")

    # 检查断言失败
    asserts = [f for f in os.listdir(output_dir) if f.endswith('.assert.err')]
    if asserts:
        results.append(f"\n发现 {len(asserts)} 个断言失败")

    # 统计覆盖率
    info_file = os.path.join(output_dir, "info")
    if os.path.exists(info_file):
        with open(info_file, 'r') as f:
            info_content = f.read()
            results.append(f"\n执行信息:\n{info_content}")

    return '\n'.join(results)

def generate_test_cases(output_dir: str, binary: str) -> str:
    """从KLEE结果生成具体的测试用例"""
    if not os.path.exists(output_dir):
        return f"KLEE输出目录 {output_dir} 不存在"

    test_files = [f for f in os.listdir(output_dir) if f.endswith('.ktest')]
    results = []

    for test_file in test_files[:5]:  # 只处理前5个
        test_path = os.path.join(output_dir, test_file)

        # 使用ktest-tool提取测试数据
        cmd = f"ktest-tool {test_path}"
        try:
            output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            results.append(f"\n测试用例 {test_file}:")
            results.append(output.stdout)
        except:
            results.append(f"无法解析测试用例 {test_file}")

    return '\n'.join(results)
```

```python
# 位置：openhands/runtime/plugins/agent_skills/security/analysis_skills.py

def check_binary_security(binary: str) -> str:
    """检查二进制文件的安全特性"""
    # 基础文件信息
    file_cmd = f"file {binary}"
    file_info = subprocess.run(file_cmd, shell=True, capture_output=True, text=True)

    # checksec检查
    checksec_cmd = f"checksec --file={binary}"
    try:
        checksec_info = subprocess.run(checksec_cmd, shell=True,
                                     capture_output=True, text=True)
        security_info = checksec_info.stdout
    except:
        # 如果checksec不可用，手动检查
        security_info = "checksec不可用，执行基础检查...\n"

        # 检查NX
        nx_check = subprocess.run(f"readelf -l {binary} | grep GNU_STACK",
                                shell=True, capture_output=True, text=True)
        if "RW" in nx_check.stdout and "RWE" not in nx_check.stdout:
            security_info += "NX: 启用\n"
        else:
            security_info += "NX: 禁用\n"

        # 检查PIE
        pie_check = subprocess.run(f"readelf -h {binary} | grep 'Type:'",
                                 shell=True, capture_output=True, text=True)
        if "DYN" in pie_check.stdout:
            security_info += "PIE: 启用\n"
        else:
            security_info += "PIE: 禁用\n"

    return f"文件信息:\n{file_info.stdout}\n\n安全特性:\n{security_info}"

def extract_functions(binary: str) -> str:
    """提取二进制文件中的函数列表"""
    # 使用objdump提取函数
    cmd = f"objdump -t {binary} | grep -E ' F .text' | awk '{{print $NF}}' | sort"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        functions = result.stdout.strip().split('\n')

        output = f"发现 {len(functions)} 个函数:\n"

        # 显示前20个函数
        for func in functions[:20]:
            output += f"  - {func}\n"

        if len(functions) > 20:
            output += f"  ... 还有 {len(functions) - 20} 个函数\n"

        return output
    except Exception as e:
        return f"提取函数失败: {str(e)}"

def find_dangerous_functions(binary: str) -> str:
    """查找潜在危险函数的使用"""
    dangerous_funcs = [
        'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
        'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf', 'vsscanf',
        'strtok', 'strtok_r', 'strncpy', 'strncat',
        'memcpy', 'memmove', 'bcopy',
        'system', 'popen', 'execve', 'execl', 'execlp', 'execle',
        'malloc', 'free', 'realloc', 'calloc'
    ]

    results = []

    # 检查导入的函数
    for func in dangerous_funcs:
        cmd = f"objdump -T {binary} 2>/dev/null | grep -i {func}"
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if output.stdout.strip():
            results.append(f"发现危险函数: {func}")

    # 检查PLT
    plt_cmd = f"objdump -d {binary} | grep '@plt' | grep -E '({'|'.join(dangerous_funcs)})'"
    plt_output = subprocess.run(plt_cmd, shell=True, capture_output=True, text=True)

    if plt_output.stdout:
        results.append("\nPLT中的危险函数调用:")
        results.append(plt_output.stdout)

    if not results:
        return "未发现明显的危险函数使用"

    return '\n'.join(results)

def generate_security_report(binary: str, analysis_results: Dict) -> str:
    """生成安全分析报告"""
    report = []
    report.append("=" * 60)
    report.append(f"安全分析报告 - {binary}")
    report.append("=" * 60)
    report.append(f"\n生成时间: {subprocess.run('date', shell=True, capture_output=True, text=True).stdout.strip()}")

    # 基础信息
    report.append("\n## 1. 二进制文件信息")
    report.append(check_binary_security(binary))

    # 危险函数
    report.append("\n## 2. 潜在危险函数")
    report.append(find_dangerous_functions(binary))

    # Fuzzing结果
    if 'fuzzing' in analysis_results:
        report.append("\n## 3. 模糊测试结果")
        report.append(f"发现崩溃数: {analysis_results['fuzzing'].get('crashes', 0)}")
        report.append(f"执行时间: {analysis_results['fuzzing'].get('runtime', 'Unknown')}")
        report.append(f"覆盖率: {analysis_results['fuzzing'].get('coverage', 'Unknown')}")

    # 崩溃分析
    if 'crashes' in analysis_results:
        report.append("\n## 4. 崩溃分析")
        for i, crash in enumerate(analysis_results['crashes'][:5]):
            report.append(f"\n### 崩溃 {i+1}")
            report.append(f"信号: {crash.get('signal', 'Unknown')}")
            report.append(f"位置: {crash.get('location', 'Unknown')}")
            report.append(f"可利用性: {crash.get('exploitability', 'Unknown')}")

    # 符号执行结果
    if 'symbolic' in analysis_results:
        report.append("\n## 5. 符号执行结果")
        report.append(f"生成测试用例: {analysis_results['symbolic'].get('test_cases', 0)}")
        report.append(f"发现错误: {analysis_results['symbolic'].get('errors', 0)}")

    # 建议
    report.append("\n## 6. 安全建议")
    report.append("- 替换所有危险函数为安全版本")
    report.append("- 启用所有安全编译选项（-fstack-protector-all, -D_FORTIFY_SOURCE=2等）")
    report.append("- 实施输入验证和边界检查")
    report.append("- 考虑使用内存安全的编程语言重写关键组件")

    return '\n'.join(report)
```

## 三、环境配置详细步骤

### 3.1 Docker镜像构建

#### 方案A：修改现有Dockerfile模板（推荐）

```dockerfile
# 文件：openhands/runtime/utils/runtime_templates/Dockerfile.j2
# 在现有模板中添加以下内容

{% if security_tools_enabled | default(false) %}
# ===== 安全分析工具安装 =====

# 1. 安装AFL++
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    python3-setuptools \
    gcc-multilib \
    libtool \
    automake \
    autoconf \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# 从源码安装最新版AFL++
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git /tmp/aflplusplus && \
    cd /tmp/aflplusplus && \
    make distrib && \
    make install && \
    cd / && rm -rf /tmp/aflplusplus

# 2. 安装GDB和插件
RUN apt-get update && apt-get install -y \
    gdb \
    gdb-multiarch \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# 安装GDB增强插件
RUN pip3 install --no-cache-dir \
    pwntools \
    ropper \
    keystone-engine \
    capstone \
    unicorn

# 安装exploitable插件
RUN cd /tmp && \
    git clone https://github.com/jfoote/exploitable.git && \
    echo "source /tmp/exploitable/exploitable/exploitable.py" >> ~/.gdbinit

# 安装pwndbg
RUN cd /opt && \
    git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh

# 3. 安装KLEE
# 注意：KLEE安装较复杂，这里使用简化版本
RUN apt-get update && apt-get install -y \
    clang-11 \
    llvm-11 \
    llvm-11-dev \
    llvm-11-tools \
    z3 \
    libz3-dev \
    && rm -rf /var/lib/apt/lists/*

# 使用预编译的KLEE（如果可用）
# 或者从源码构建（需要较长时间）
RUN pip3 install --no-cache-dir wllvm

# 4. 安装辅助工具
RUN apt-get update && apt-get install -y \
    ltrace \
    strace \
    file \
    checksec \
    radare2 \
    binwalk \
    foremost \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

# 5. 配置环境变量
ENV AFL_PATH=/usr/local/lib/afl
ENV PATH=$PATH:/usr/local/lib/afl
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# 6. 创建工作目录
RUN mkdir -p /workspace/security/{fuzzing,crashes,symbolic,reports}

{% endif %}
```

#### 方案B：独立的SecurityAgent镜像

```dockerfile
# 文件：openhands/runtime/security/Dockerfile

FROM ubuntu:22.04

# 基础依赖
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装OpenHands基础环境
# ... (复制必要的OpenHands组件)

# 安装安全工具（同上）
# ...

# 设置入口点
WORKDIR /workspace
CMD ["/bin/bash"]
```

### 3.2 配置文件设置

```python
# 文件：openhands/core/config/security_config.py

from dataclasses import dataclass
from typing import Optional

@dataclass
class SecurityConfig:
    """SecurityAgent配置"""

    # 工具启用开关
    enable_afl: bool = True
    enable_gdb: bool = True
    enable_klee: bool = True

    # AFL++配置
    afl_timeout: int = 3600  # 默认运行1小时
    afl_memory_limit: int = 2048  # MB
    afl_cores: int = 1  # 并行核心数
    afl_dict_path: Optional[str] = None  # 字典文件路径

    # GDB配置
    gdb_timeout: int = 30  # 单次分析超时
    gdb_batch_size: int = 10  # 批量分析数量

    # KLEE配置
    klee_timeout: int = 1800  # 默认运行30分钟
    klee_memory_limit: int = 2000  # MB
    klee_max_forks: int = 256

    # 输出配置
    report_format: str = "markdown"  # markdown/json/html
    save_all_crashes: bool = True
    auto_minimize_corpus: bool = True
```

### 3.3 启动和使用流程

#### 1. 构建镜像

```bash
# 使用修改后的模板构建
cd /path/to/OpenHands
make build SECURITY_TOOLS_ENABLED=true

# 或者直接使用docker build
docker build -t openhands-security:latest \
  --build-arg SECURITY_TOOLS_ENABLED=true \
  -f containers/runtime/Dockerfile .
```

#### 2. 启动SecurityAgent

```python
# 方式1：命令行启动
openhands-cli --agent SecurityAgent --runtime docker \
  --runtime-image openhands-security:latest \
  --task "分析 /workspace/target_binary 的安全性"

# 方式2：Python API启动
from openhands import SecurityAgent, Runtime

# 创建运行时
runtime = Runtime(
    image="openhands-security:latest",
    volumes={
        "/path/to/target": "/workspace"
    }
)

# 创建Agent
agent = SecurityAgent(
    runtime=runtime,
    config={
        "security_tools_enabled": True,
        "afl_cores": 4,
        "afl_timeout": 7200
    }
)

# 执行任务
result = agent.run("全面分析 /workspace/binary 的安全漏洞")
```

#### 3. 典型使用场景

```python
# 场景1：快速安全检查
task = """
1. 检查 /workspace/server 的安全编译选项
2. 查找危险函数调用
3. 运行30分钟的快速fuzzing
4. 生成初步安全报告
"""

# 场景2：深度漏洞挖掘
task = """
对 /workspace/parser 进行深度安全分析：
1. 使用AFL++进行24小时fuzzing（使用8个CPU核心）
2. 对所有崩溃进行详细分析
3. 使用KLEE进行符号执行，特别关注输入验证逻辑
4. 尝试构造可利用的PoC
5. 生成详细的技术报告和修复建议
"""

# 场景3：源码审计辅助
task = """
项目路径：/workspace/project
1. 编译项目的fuzzing版本（使用afl-clang-fast）
2. 自动生成fuzzing种子
3. 运行智能fuzzing，重点测试解析功能
4. 分析代码覆盖率
5. 对发现的问题提供代码级修复建议
"""
```

## 四、微代理知识库详细内容

### 4.1 security_workflow.md（完整版）

```markdown
---
name: security_workflow
triggers:
  - security analysis
  - vulnerability assessment
  - 安全分析
  - 漏洞挖掘
---

# 安全分析总体工作流

## 1. 初始侦察阶段

### 1.1 文件类型识别
```bash
file target_binary
strings -n 10 target_binary | head -50
ldd target_binary  # 查看动态链接库
```

### 1.2 安全机制检查
```bash
checksec --file=target_binary
# 或手动检查
readelf -h target_binary | grep -E 'Type:|Machine:'
readelf -l target_binary | grep -E 'GNU_STACK|GNU_RELRO'
```

### 1.3 函数分析
```bash
# 查看导出函数
objdump -T target_binary | grep -E '\.text|FUNC'

# 查找危险函数
objdump -T target_binary | grep -E 'gets|strcpy|sprintf|system'

# 反汇编main函数
objdump -d target_binary | grep -A 200 '<main>:'
```

## 2. 选择分析策略

### 2.1 判断标准
- **有源码**：优先使用源码插桩fuzzing + KLEE符号执行
- **无源码 + 小程序**：QEMU模式fuzzing + 手工逆向
- **无源码 + 大程序**：黑盒fuzzing + 动态分析
- **网络程序**：需要特殊的网络fuzzing适配

### 2.2 环境准备
```bash
# 创建工作目录
mkdir -p ~/security_analysis/{input,output,crashes,reports}

# 如果有源码，编译插桩版本
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure
make clean && make

# 准备初始种子
echo "test" > ~/security_analysis/input/seed1
# 如果是特定格式，准备对应样本
```

## 3. 模糊测试阶段

### 3.1 单核Fuzzing
```bash
# 基础fuzzing
afl-fuzz -i input -o output -- ./target @@

# 带字典的fuzzing
afl-fuzz -i input -o output -x dict.txt -- ./target @@

# QEMU模式（无源码）
afl-fuzz -Q -i input -o output -- ./target @@
```

### 3.2 多核并行Fuzzing
```bash
# 主节点
afl-fuzz -i input -o output -M fuzzer01 -- ./target @@

# 从节点（在其他终端）
afl-fuzz -i input -o output -S fuzzer02 -- ./target @@
afl-fuzz -i input -o output -S fuzzer03 -d -- ./target @@  # 确定性变异
afl-fuzz -i input -o output -S fuzzer04 -n -- ./target @@  # 非确定性变异
```

### 3.3 监控和优化
```bash
# 实时监控
watch -n 1 afl-whatsup output

# 查看统计信息
cat output/fuzzer01/fuzzer_stats

# 语料库最小化
afl-cmin -i output/queue -o minimized_corpus -- ./target @@

# 测试用例最小化
afl-tmin -i crash_file -o minimized_crash -- ./target @@
```

## 4. 崩溃分析阶段

### 4.1 崩溃收集和分类
```bash
# 查看崩溃数量
ls output/*/crashes/id:* | wc -l

# 按唯一性分类
afl-collect -r output -e gdb_script -- ./target @@
```

### 4.2 GDB批量分析
```bash
# 分析脚本
cat > analyze_crashes.sh << 'EOF'
#!/bin/bash
for crash in output/*/crashes/id:*; do
    echo "=== Analyzing $crash ==="
    gdb -batch \
        -ex "file ./target" \
        -ex "run < $crash" \
        -ex "bt" \
        -ex "info registers" \
        -ex "x/10i \$rip" \
        -ex "quit" \
        2>&1 | tee "${crash}.analysis"
done
EOF

chmod +x analyze_crashes.sh
./analyze_crashes.sh
```

### 4.3 可利用性评估
- **栈溢出特征**：
  - 返回地址被覆盖（RIP包含无效地址）
  - 栈金丝雀检测（stack smashing detected）
  - 局部变量覆盖

- **堆溢出特征**：
  - malloc/free崩溃
  - 堆元数据损坏
  - double free检测

- **格式化字符串**：
  - printf系列函数崩溃
  - 可控的格式化参数

## 5. 符号执行阶段（如有源码）

### 5.1 编译LLVM bitcode
```bash
# 编译为bitcode
clang -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone source.c -o source.bc

# 如果有多个源文件
llvm-link file1.bc file2.bc -o combined.bc
```

### 5.2 运行KLEE
```bash
# 基础运行
klee --max-time=3600 --max-memory=2000 source.bc

# 优化选项
klee \
  --max-time=3600 \
  --max-memory=2000 \
  --max-instruction-time=30 \
  --max-solver-time=30 \
  --use-forked-solver \
  --search=random-path \
  source.bc
```

### 5.3 分析KLEE结果
```bash
# 查看生成的测试用例
ls klee-last/*.ktest | wc -l

# 提取测试输入
for test in klee-last/*.ktest; do
    ktest-tool "$test"
done

# 查看发现的错误
cat klee-last/*.err
```

## 6. 漏洞验证和利用

### 6.1 崩溃重现
```bash
# 确认崩溃稳定性
for i in {1..10}; do
    ./target < crash_file
    echo "Run $i: $?"
done
```

### 6.2 构造PoC
```python
# 使用pwntools构造exploit
from pwn import *

# 分析崩溃偏移
pattern = cyclic(200)
with open("pattern_input", "wb") as f:
    f.write(pattern)

# 运行并查找偏移
# gdb ./target
# run < pattern_input
# x/s $rsp
offset = cyclic_find(0x61616161)  # 替换为实际值

# 构造exploit
payload = b"A" * offset
payload += p64(0xdeadbeef)  # 目标地址
```

## 7. 报告生成

### 7.1 收集所有结果
```bash
mkdir -p report/{crashes,coverage,symbolic}
cp output/*/crashes/id:* report/crashes/
cp klee-last/*.err report/symbolic/
```

### 7.2 生成技术报告
应包含：
1. 执行摘要
2. 测试环境和配置
3. 发现的漏洞列表
4. 每个漏洞的详细分析
5. 漏洞利用可能性评估
6. 修复建议
7. 附录（崩溃样本、PoC代码）

## 常见问题处理

### AFL++无输出
- 检查是否正确插桩
- 确认种子文件有效
- 查看是否有权限问题

### GDB分析超时
- 使用timeout命令限制运行时间
- 考虑简化分析脚本
- 检查是否有无限循环

### KLEE内存不足
- 减少--max-memory参数
- 使用--max-forks限制分支
- 简化符号输入大小
```

### 4.2 afl_fuzzing.md

```markdown
---
name: afl_fuzzing
triggers:
  - fuzzing
  - afl
  - 模糊测试
---

# AFL++高级使用指南

## 基础概念

AFL++是一个覆盖引导的模糊测试工具，通过监控程序执行路径来生成高质量的测试输入。

## 编译插桩

### 1. C/C++程序
```bash
# 使用afl-clang-fast（推荐）
export CC=afl-clang-fast
export CXX=afl-clang-fast++
./configure --disable-shared
make clean && make

# 使用afl-gcc（兼容性更好）
export CC=afl-gcc
export CXX=afl-g++
make

# LTO模式（Link Time Optimization）
export CC=afl-clang-lto
export CXX=afl-clang-lto++
make
```

### 2. 比较覆盖（CMPLOG）
```bash
# 编译CMPLOG版本（用于复杂比较）
export AFL_LLVM_CMPLOG=1
make clean && make
# 使用时：afl-fuzz -c ./target_cmplog ...
```

### 3. 无源码二进制
```bash
# QEMU模式
afl-fuzz -Q -i input -o output -- ./binary

# Frida模式（更快）
afl-fuzz -O -i input -o output -- ./binary
```

## 高级fuzzing技巧

### 1. 种子语料库优化
```bash
# 收集初始种子
mkdir corpus
find /usr/share -name "*.xml" -size -5k -exec cp {} corpus/ \;

# 语料库最小化
afl-cmin -i corpus -o corpus_min -- ./target @@

# 单个文件最小化
afl-tmin -i big_file -o small_file -- ./target @@
```

### 2. 字典使用
```bash
# 使用现有字典
afl-fuzz -i input -o output -x dict.txt -- ./target @@

# 自动生成字典
afl-fuzz -i input -o output -D -- ./target @@

# 从源码提取字典
python3 dictutils.py source.c > auto_dict.txt
```

### 3. 并行fuzzing策略
```bash
# CPU核心分配
# 主fuzzer（1个）
afl-fuzz -i input -o output -M main -- ./target @@

# 确定性fuzzer（CPU的25%）
for i in {1..2}; do
  afl-fuzz -i input -o output -S determ$i -- ./target @@
done

# 混沌fuzzer（CPU的25%）
for i in {1..2}; do
  afl-fuzz -i input -o output -S chaos$i -d -- ./target @@
done

# 探索fuzzer（CPU的50%）
for i in {1..4}; do
  afl-fuzz -i input -o output -S explore$i -p explore -- ./target @@
done
```

### 4. 性能优化
```bash
# 系统配置
sudo afl-system-config

# 持久模式（需要修改源码）
# 在目标程序中添加：
__AFL_FUZZ_INIT();
while (__AFL_LOOP(1000)) {
  // 重置状态
  // 处理输入
}

# 共享内存模式
export AFL_TMPDIR=/dev/shm
```

## 特殊场景

### 1. 网络程序fuzzing
```bash
# 使用afl-network-proxy
afl-network-server 8080 &
afl-fuzz -i input -o output -- afl-network-client 8080

# 使用preeny
LD_PRELOAD=desock.so afl-fuzz -i input -o output -- ./server
```

### 2. 多线程程序
```bash
# 禁用线程（如果可能）
export AFL_NO_FORKSRV=1
afl-fuzz -i input -o output -- ./target @@

# 使用持久模式处理线程
```

### 3. 自定义mutator
```python
# custom_mutator.py
def init(seed):
    pass

def fuzz(buf, add_buf, max_size):
    # 自定义变异逻辑
    return mutated_buf

def describe(max_description_length):
    return "Custom JSON mutator"

# 使用
export AFL_CUSTOM_MUTATOR_LIBRARY=./custom_mutator.so
afl-fuzz -i input -o output -- ./target @@
```

## 崩溃分析自动化

### 1. 崩溃分类
```bash
# 使用afl-collect
afl-collect -r output -e gdb_script -- ./target @@

# 手动分类脚本
for crash in output/*/crashes/id:*; do
    hash=$(md5sum <(gdb -batch -ex "run < $crash" -ex "bt" ./target 2>&1) | cut -d' ' -f1)
    mkdir -p classified/$hash
    cp $crash classified/$hash/
done
```

### 2. 崩溃最小化
```bash
# 批量最小化
for crash in output/*/crashes/id:*; do
    output_name="minimized_$(basename $crash)"
    afl-tmin -i "$crash" -o "$output_name" -- ./target @@
done
```

## 覆盖率分析

### 1. 生成覆盖率报告
```bash
# 编译时添加覆盖率选项
export CFLAGS="--coverage"
export LDFLAGS="--coverage"
make

# 运行测试
for test in output/queue/id:*; do
    ./target < "$test"
done

# 生成报告
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_report
```

### 2. 可视化
```bash
# 使用afl-plot
afl-plot output/default plot_output

# 实时监控
afl-whatsup -s output
```

## 常见问题解决

### 1. "Suboptimal: Instrumented binary is a shell script"
- 直接指定二进制文件，不要用脚本包装
- 或使用 AFL_SKIP_BIN_CHECK=1

### 2. "Fork server handshake failed"
- 检查程序是否正常启动
- 尝试增加内存限制：-m none
- 使用 AFL_NO_FORKSRV=1（性能会降低）

### 3. 性能优化建议
- 使用持久模式（可提升10x性能）
- 禁用不必要的检查：AFL_DISABLE_TRIM=1
- 使用RAM磁盘：AFL_TMPDIR=/dev/shm
```

## 五、完整使用示例

### 5.1 从零开始的安全分析

```bash
# 1. 启动SecurityAgent
$ openhands --agent SecurityAgent

Agent: 我是SecurityAgent，准备进行安全分析。请提供目标文件路径。

User: 分析 /workspace/vulnerable_server 的安全性

Agent: 开始对 /workspace/vulnerable_server 进行全面安全分析。

# 2. 初始侦察
Agent执行: file /workspace/vulnerable_server
输出: ELF 64-bit LSB executable, x86-64, dynamically linked

Agent执行: checksec --file=/workspace/vulnerable_server
输出:
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE

Agent: 发现目标程序缺少关键安全保护机制（无栈保护、无PIE），可能存在漏洞。

# 3. 函数分析
Agent执行: objdump -T /workspace/vulnerable_server | grep -E 'gets|strcpy'
输出:
    0000000000400540  DF *UND*  0000000000000000  GLIBC_2.2.5 gets
    0000000000400550  DF *UND*  0000000000000000  GLIBC_2.2.5 strcpy

Agent: 检测到危险函数gets和strcpy的使用，高概率存在缓冲区溢出漏洞。

# 4. 准备fuzzing
Agent执行: mkdir -p /tmp/fuzz/{input,output}
Agent执行: echo "test" > /tmp/fuzz/input/seed1
Agent执行: python3 -c "print('A'*100)" > /tmp/fuzz/input/seed2

# 5. 执行fuzzing
Agent执行: timeout 1800 afl-fuzz -i /tmp/fuzz/input -o /tmp/fuzz/output -- /workspace/vulnerable_server

[... 30分钟后 ...]

Agent执行: ls /tmp/fuzz/output/default/crashes/ | wc -l
输出: 15

Agent: Fuzzing发现15个崩溃样本，开始详细分析。

# 6. 崩溃分析
Agent执行:
for crash in /tmp/fuzz/output/default/crashes/id:*; do
    echo "=== $crash ==="
    gdb -batch -ex "run < $crash" -ex "bt" -ex "info registers" /workspace/vulnerable_server 2>&1
done

输出:
Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
#0  0x0000414141414141 in ?? ()
#1  0x4141414141414141 in ?? ()
...

Agent: 确认存在栈溢出漏洞，返回地址被覆盖为0x414141...（'AAA...'）。

# 7. 漏洞利用分析
Agent执行: python3 -c "
from pwn import *
crash = open('/tmp/fuzz/output/default/crashes/id:000000', 'rb').read()
print(f'崩溃输入长度: {len(crash)}')
print(f'崩溃输入内容: {crash[:50]}...')
"

# 8. 生成报告
Agent: 生成安全分析报告...

## 安全分析报告 - vulnerable_server

### 执行摘要
- **严重程度**: 高危
- **漏洞类型**: 栈缓冲区溢出
- **可利用性**: 高（无保护机制）

### 详细发现
1. **危险函数使用**
   - gets() 函数：无边界检查的输入
   - strcpy() 函数：无长度限制的字符串复制

2. **安全机制缺失**
   - 无栈保护（No Stack Canary）
   - 无地址随机化（No PIE）
   - 部分RELRO

3. **Fuzzing结果**
   - 运行时间：30分钟
   - 发现崩溃：15个
   - 唯一崩溃：3种

4. **漏洞细节**
   - 溢出位置：main函数局部缓冲区
   - 溢出偏移：120字节
   - 控制流劫持：可控制RIP寄存器

### 修复建议
1. **立即修复**
   - 替换gets()为fgets()或getline()
   - 替换strcpy()为strncpy()或strlcpy()
   - 添加输入长度验证

2. **编译选项**
   ```bash
   gcc -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -fPIE
   ```

3. **代码审计**
   - 审查所有输入处理函数
   - 实施边界检查
   - 考虑使用安全编码标准

### 附录
- 崩溃样本已保存至: /tmp/fuzz/output/default/crashes/
- 最小化PoC: /workspace/security_report/poc.txt
```

### 5.2 高级场景：源码可用时的深度分析

```python
# 用户提供源码项目
User: 对 /workspace/json_parser 项目进行深度安全审计，源码在 /workspace/json_parser/src

Agent: 开始深度安全审计，我将结合静态分析、动态fuzzing和符号执行。

# 1. 代码静态分析
Agent执行: find /workspace/json_parser/src -name "*.c" -o -name "*.h" | xargs grep -n "strcpy\|strcat\|sprintf\|gets"

# 2. 编译多个版本
Agent执行: cd /workspace/json_parser && make clean

# 普通版本
Agent执行: make

# AFL++插桩版本
Agent执行: make clean && CC=afl-clang-fast make

# ASAN版本
Agent执行: make clean && CC=clang CFLAGS="-fsanitize=address -g" make

# KLEE版本
Agent执行: make clean && CC=clang CFLAGS="-emit-llvm -c -g -O0" make

# 3. 智能种子生成
Agent: 分析代码发现这是JSON解析器，生成专门的测试种子...

Agent执行: python3 << 'EOF'
import json
import os

os.makedirs("/tmp/json_seeds", exist_ok=True)

# 基础JSON
seeds = [
    '{}',
    '[]',
    '{"key": "value"}',
    '[1, 2, 3]',
    '{"nested": {"deep": "value"}}',
    '{"array": [1, "two", true, null]}',
]

# 边界测试
seeds.append('{"long": "' + 'A' * 1000 + '"}')
seeds.append('[' + ','.join(['1'] * 1000) + ']')
seeds.append('{' + ','.join([f'"k{i}": {i}' for i in range(100)]) + '}')

# 恶意输入
seeds.append('{"unclosed": "string')
seeds.append('{"key": "\x00\x01\x02"}')
seeds.append('{"unicode": "\\uD800\\uDC00"}')

for i, seed in enumerate(seeds):
    with open(f"/tmp/json_seeds/seed_{i:03d}.json", "w") as f:
        f.write(seed)
EOF

# 4. 并行fuzzing（使用8核）
Agent: 启动8核并行fuzzing以提高效率...

# 5. 符号执行
Agent执行: klee --max-time=3600 --max-memory=2000 /workspace/json_parser/json_parser.bc

# 6. 结合所有结果生成综合报告...
```

## 六、故障排除和优化

### 6.1 常见问题解决

```python
# 问题1：Docker镜像过大
解决方案：
- 使用多阶段构建
- 只安装必要的工具
- 清理apt缓存和临时文件

# 问题2：Fuzzing占用过多资源
解决方案：
- 使用cgroups限制资源
- 设置合理的超时时间
- 使用nice调整优先级

# 问题3：分析结果不准确
解决方案：
- 增加分析时间
- 优化种子质量
- 调整fuzzing策略
```

### 6.2 性能优化建议

```python
# 1. 使用RAM磁盘
export AFL_TMPDIR=/dev/shm

# 2. 并行分析
- 合理分配CPU核心
- 使用不同的fuzzing策略
- 定期同步结果

# 3. 智能种子生成
- 基于代码结构生成
- 使用历史崩溃样本
- 结合符号执行结果
```

## 七、总结

这个详细的SecurityAgent设计方案具有以下特点：

1. **实施简单**：主要通过Agent Skills调用命令行工具
2. **功能完整**：涵盖fuzzing、崩溃分析、符号执行全流程
3. **易于扩展**：可以轻松添加新的安全工具
4. **智能分析**：充分利用LLM的推理能力
5. **生产可用**：包含完整的错误处理和资源管理

通过这种设计，我们在不修改OpenHands核心架构的前提下，实现了强大的安全分析能力。
