# SecurityAgent使用指南

SecurityAgent是基于OpenHands的专业安全分析代理，集成了AFL++、GDB、KLEE等专业安全工具，专门用于漏洞发现、崩溃分析和安全评估。

## 快速开始

### 1. 环境准备

#### 使用预构建的Docker镜像（推荐）

```bash
# 构建SecurityAgent运行时环境
cd containers/security
./build-security-runtime.sh

# 验证工具安装
docker run --rm openhands-security:latest check-security-tools
```

#### 手动安装（本地开发）

```bash
# 安装AFL++
sudo apt-get install afl++

# 安装GDB和增强插件
sudo apt-get install gdb
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# 安装Python安全库
pip install pwntools capstone keystone-engine

# 安装二进制分析工具
sudo apt-get install checksec binutils radare2
```

### 2. 启动SecurityAgent

#### 方式一：命令行启动

```bash
# 使用SecurityAgent Docker镜像
export RUNTIME_IMAGE=openhands-security:latest
openhands --agent SecurityAgent --runtime docker

# 或者使用本地环境
openhands --agent SecurityAgent --task "分析 /path/to/binary 的安全性"
```

#### 方式二：Python API

```python
from openhands.agenthub.security_agent import SecurityAgent
from openhands.core.config import AgentConfig
from openhands.llm.llm import LLM

# 创建LLM和配置
llm = LLM(config=llm_config)
config = AgentConfig()

# 创建SecurityAgent
agent = SecurityAgent(llm, config)

# 执行安全分析
result = agent.run("全面分析 /workspace/target_binary 的安全漏洞")
```

## 使用示例

### 基础安全分析

```bash
用户: 分析 /workspace/server 的安全性

SecurityAgent: 开始对 /workspace/server 进行安全分析...

# 1. 基础侦察
检查文件类型和安全特性...
发现：ELF 64-bit可执行文件，缺少栈保护和PIE

# 2. 危险函数检查
发现危险函数：gets(), strcpy(), sprintf()

# 3. 执行模糊测试
启动AFL++进行30分钟的模糊测试...
发现12个崩溃样本

# 4. 崩溃分析
使用GDB分析崩溃...
确认栈溢出漏洞，可控制返回地址

# 5. 生成报告
严重程度：高危
建议：立即替换危险函数，启用安全编译选项
```

### 深度漏洞挖掘

```bash
用户: 对 /workspace/parser 进行24小时深度分析，包括符号执行

SecurityAgent: 执行深度安全分析...

# 1. 编译插桩版本
使用afl-clang-fast重新编译目标程序...

# 2. 多核并行fuzzing
启动8核并行AFL++实例...
- 主fuzzer（确定性变异）
- 3个从fuzzer（随机变异）
- 2个探索fuzzer（路径优先）
- 1个CMPLOG fuzzer（复杂比较）

# 3. 符号执行分析
编译LLVM bitcode...
运行KLEE符号执行...
生成125个测试用例，发现3个错误路径

# 4. 综合分析
发现35个崩溃，分类为：
- 栈溢出：8个（高危）
- 堆损坏：12个（高危）
- 空指针解引用：15个（中危）

# 5. 可利用性评估
高危漏洞可远程利用，需立即修复
提供详细的PoC和修复方案
```

### 源码审计辅助

```bash
用户: 帮我审计 /workspace/project 的源码安全性

SecurityAgent: 开始源码安全审计...

# 1. 静态分析
扫描危险函数使用...
发现问题：
- main.c:45 使用strcpy无边界检查
- parser.c:123 scanf可能导致缓冲区溢出
- network.c:78 系统调用参数未验证

# 2. 编译安全版本
编译fuzzing版本和调试版本...

# 3. 智能测试用例生成
基于代码结构生成测试输入...
重点测试解析函数和输入处理

# 4. 自动化验证
验证发现的问题...
生成最小化PoC

# 5. 修复建议
提供具体的代码修改建议：
- 第45行：strcpy(dst, src) → strncpy(dst, src, sizeof(dst)-1)
- 第123行：添加输入长度限制
- 第78行：添加参数白名单验证
```

## 核心功能详解

### 1. 二进制安全分析

SecurityAgent使用多种工具进行综合安全分析：

```python
# 使用analysis_skills进行二进制分析
check_binary_security("/path/to/binary")
# 检查：NX、PIE、RELRO、Stack Canary等安全特性

find_dangerous_functions("/path/to/binary") 
# 识别：gets、strcpy、sprintf等危险函数

extract_functions("/path/to/binary")
# 提取：函数列表和调用关系
```

### 2. 模糊测试（Fuzzing）

使用AFL++进行覆盖率引导的模糊测试：

```python
# 启动AFL++模糊测试
start_fuzzing(
    binary="/path/to/target",
    input_dir="/path/to/seeds", 
    output_dir="/path/to/output",
    cores=4,           # 4核并行
    timeout=7200       # 2小时
)

# 监控fuzzing状态
check_fuzzing_status("/path/to/output")

# 收集崩溃样本
collect_crashes("/path/to/output")
```

### 3. 崩溃分析

使用GDB进行深度崩溃分析：

```python
# 分析单个崩溃
analyze_crash(
    binary="/path/to/target",
    crash_file="/path/to/crash", 
    timeout=30
)

# 批量分析崩溃
batch_analyze_crashes(
    binary="/path/to/target",
    crash_dir="/path/to/crashes",
    max_crashes=20
)

# 可利用性评估
check_exploitability(
    binary="/path/to/target",
    crash_file="/path/to/crash"
)
```

### 4. 符号执行

使用KLEE进行路径探索和约束求解：

```python
# 编译为LLVM bitcode
compile_for_klee("source.c", "source.bc")

# 运行符号执行
run_symbolic_execution(
    "source.bc",
    max_time=3600,     # 1小时
    max_memory=2000    # 2GB内存
)

# 分析结果
analyze_klee_results("klee-out-source")

# 生成测试用例
generate_test_cases("klee-out-source", max_cases=50)
```

### 5. 报告生成

生成专业的安全分析报告：

```python
# 生成综合报告
generate_security_report(
    binary="/path/to/target",
    analysis_results={
        "fuzzing": fuzzing_results,
        "crashes": crash_analysis,
        "symbolic": klee_results
    },
    output_file="/path/to/report.md",
    report_format="markdown"
)
```

## 最佳实践

### 1. 分析策略选择

根据不同情况选择合适的分析策略：

| 场景 | 推荐策略 | 工具组合 |
|------|----------|----------|
| 有源码 + 小程序 | 白盒分析 | AFL++(插桩) + KLEE |
| 有源码 + 大程序 | 混合分析 | AFL++(插桩) + 静态分析 |
| 无源码 + 任意程序 | 黑盒分析 | AFL++(QEMU) + GDB |
| 网络服务 | 协议分析 | AFL++(网络代理) + 协议fuzzing |

### 2. 性能优化

提高分析效率的技巧：

```bash
# 使用内存文件系统加速fuzzing
export AFL_TMPDIR=/dev/shm

# 并行分析策略
- 主fuzzer：1个（确定性变异）
- 从fuzzer：CPU核心数-2个（随机变异）
- 探索fuzzer：1个（新路径优先）

# 优化种子语料库
afl-cmin -i raw_seeds -o optimized_seeds -- ./target @@
```

### 3. 安全注意事项

确保分析过程的安全性：

- **隔离环境**：始终在容器或虚拟机中进行分析
- **资源限制**：设置合理的内存和时间限制
- **数据保护**：不要在分析中包含敏感生产数据
- **权限控制**：使用最小必要权限原则

## 故障排除

### 常见问题

1. **AFL++无法启动**
   ```bash
   # 检查插桩是否正确
   ./target < seed_input  # 应该正常运行
   
   # 检查权限和环境
   export AFL_SKIP_CPUFREQ=1
   ```

2. **GDB分析超时**
   ```bash
   # 增加超时时间或简化分析
   analyze_crash(binary, crash, timeout=60)
   ```

3. **KLEE内存不足**
   ```bash
   # 减少内存限制或简化输入
   run_symbolic_execution(bitcode, max_memory=1000)
   ```

### 性能调优

监控和优化分析性能：

```bash
# 监控系统资源
htop
iostat -x 1

# 监控fuzzing状态
watch -n 5 afl-whatsup output

# 调整并发数量
# CPU密集型：并发数 = CPU核心数
# I/O密集型：并发数 = CPU核心数 * 2
```

## 扩展和定制

### 添加新的安全工具

1. 在`security_skills`中添加新的工具封装
2. 更新SecurityAgent的提示词
3. 添加相应的微代理知识库
4. 更新Docker环境配置

### 自定义分析流程

```python
# 创建自定义分析工作流
def custom_security_workflow(target_binary):
    # 1. 基础检查
    security_check = check_binary_security(target_binary)
    
    # 2. 根据结果选择策略
    if "No PIE" in security_check:
        # 优先进行ROP链分析
        rop_analysis = find_rop_gadgets(target_binary)
    
    # 3. 执行针对性测试
    # ...
    
    return comprehensive_report
```

## 更多资源

- **微代理知识库**：`/microagents/security_*.md`
- **Docker配置**：`/containers/security/`
- **测试用例**：`/tests/unit/test_security_agent.py`
- **AFL++文档**：https://aflplus.plus/
- **GDB手册**：https://sourceware.org/gdb/
- **KLEE教程**：https://klee.github.io/

通过SecurityAgent，您可以进行专业级的安全分析，发现潜在的安全漏洞，并获得详细的修复建议。这个工具特别适合安全研究人员、渗透测试工程师和开发团队使用。