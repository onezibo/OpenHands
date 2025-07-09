---
name: security_workflow
type: knowledge
triggers:
  - security analysis
  - vulnerability assessment
  - 安全分析
  - 漏洞挖掘
  - fuzzing workflow
  - crash analysis
  - 符号执行
---

# 安全分析总体工作流程

这是一个专业的安全分析工作流程，使用AFL++、GDB、KLEE等工具进行综合性安全评估。

## 1. 初始侦察阶段

### 1.1 CVE任务专用：Exploit链接分析（适用于CVE复现任务）

```bash
# CVE信息收集和exploit链接提取
echo "任务类型: CVE复现分析"
echo "目标CVE: [如 CVE-2018-17942]"

# 使用WebFetch分析CVE页面，提取exploit链接
# WebFetch(url="https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN", 
#          prompt="提取所有标记为exploit的链接以及其他技术参考链接")

# 分析每个exploit链接的内容
for exploit_link in extracted_links:
    echo "分析链接: $exploit_link"
    # WebFetch(url=$exploit_link, 
    #          prompt="提取CVE复现步骤、触发条件、测试用例和技术细节")
```

**CVE exploit链接分析重点**：
- **Mailing list讨论**：原始漏洞报告、技术讨论、测试用例
- **Bug reports**：具体复现步骤、环境要求、错误信息  
- **GitHub commits**：代码修复、测试用例、编译选项
- **Security advisories**：官方分析、影响评估、缓解措施

### 1.2 目标识别和基础信息收集

```bash
# 文件类型和架构分析
file target_binary
strings -n 10 target_binary | head -50

# 动态链接库依赖
ldd target_binary

# 基础安全特性检查
checksec --file=target_binary
```

### 1.3 安全机制检查

```bash
# 手动检查（如果checksec不可用）
readelf -h target_binary | grep -E 'Type:|Machine:'
readelf -l target_binary | grep -E 'GNU_STACK|GNU_RELRO'
objdump -T target_binary | grep __stack_chk_fail
```

### 1.4 函数和符号分析

```bash
# 导出函数分析
objdump -T target_binary | grep -E '\\.text|FUNC'

# 危险函数识别
objdump -T target_binary | grep -E 'gets|strcpy|sprintf|system|malloc|free'

# 反汇编关键函数
objdump -d target_binary | grep -A 50 '<main>:'
```

## 2. 分析策略选择

### 2.1 CVE任务增强决策矩阵

| 条件 | 推荐策略 | 工具组合 | CVE专用增强 |
|------|----------|----------|-------------|
| CVE + 有exploit链接 | Exploit引导复现 | WebFetch + 精确复现 + AFL++ | 优先使用exploit中的测试用例 |
| 有源码 + 小程序 | 白盒fuzzing + 符号执行 | AFL++ (插桩) + KLEE | 基于exploit信息调整种子 |
| 有源码 + 大程序 | 白盒fuzzing + 静态分析 | AFL++ (插桩) + 手工审计 | 重点分析exploit提及的函数 |
| 无源码 + 小程序 | 黑盒fuzzing + 动态分析 | AFL++ (QEMU) + GDB | 使用exploit编译选项重构环境 |
| 无源码 + 大程序 | 目标fuzzing + 热点分析 | AFL++ (QEMU) + 覆盖率分析 | 专注exploit涉及的代码路径 |
| 网络服务 | 协议fuzzing + 状态分析 | AFL++ (网络模式) + 协议分析 | 分析exploit中的网络交互 |

### 2.2 环境准备

```bash
# 创建标准化工作目录
mkdir -p ~/security_analysis/{input,output,crashes,reports,tools,cve_analysis}

# CVE任务：基于exploit信息配置环境
if [[ -n "$CVE_TASK" ]]; then
    echo "配置CVE复现环境..."
    
    # 从exploit分析中提取的编译选项
    export CC="[从exploit中获取，如clang]"
    export CFLAGS="[从exploit中获取，如-fsanitize=address -g -O0]"
    export LDFLAGS="[从exploit链接选项]"
    
    # 安装特定版本依赖（基于exploit信息）
    # apt-get install [specific-package=version]
    
    # 使用exploit中的具体测试用例作为种子
    echo "[从exploit中提取的触发输入]" > ~/security_analysis/input/exploit_seed
fi

# 常规源码编译（如可用）
export CC=${CC:-afl-clang-fast}
export CXX=${CXX:-afl-clang-fast++}
./configure --disable-shared
make clean && make

# 准备初始种子
echo "minimal_test" > ~/security_analysis/input/seed1
# 收集特定格式的样本（如XML、JSON等）
find /usr/share -name "*.xml" -size -5k -exec cp {} ~/security_analysis/input/ \\;
```

## 3. 模糊测试执行阶段

### 3.1 基础Fuzzing策略

```bash
# 单核基础fuzzing
afl-fuzz -i input -o output -- ./target @@

# 带字典的fuzzing（提高效率）
afl-fuzz -i input -o output -x dict.txt -- ./target @@

# QEMU模式（无源码二进制）
afl-fuzz -Q -i input -o output -- ./target @@
```

### 3.2 高级并行Fuzzing

```bash
# 多核并行策略（推荐4-8核）
# 主fuzzer（确定性变异）
afl-fuzz -i input -o output -M master -- ./target @@

# 从fuzzer（随机变异）
afl-fuzz -i input -o output -S slave01 -- ./target @@
afl-fuzz -i input -o output -S slave02 -d -- ./target @@  # 确定性模式
afl-fuzz -i input -o output -S slave03 -n -- ./target @@  # 非确定性模式

# 专门的探索fuzzer
afl-fuzz -i input -o output -S explore01 -p explore -- ./target @@
```

### 3.3 监控和优化

```bash
# 实时状态监控
watch -n 5 afl-whatsup output

# 性能统计
cat output/master/fuzzer_stats | grep -E 'execs_per_sec|paths_found|unique_crashes'

# 语料库优化
afl-cmin -i output/master/queue -o minimized_corpus -- ./target @@
```

## 4. 崩溃分析阶段

### 4.1 崩溃收集和初步分类

```bash
# 统计崩溃数量
find output -name "id:*" -path "*/crashes/*" | wc -l

# 崩溃文件大小分布
find output -name "id:*" -path "*/crashes/*" -exec ls -l {} \\; | awk '{print $5}' | sort -n

# 使用afl-collect进行自动分类（如可用）
afl-collect -r output -- ./target @@
```

### 4.2 GDB深度分析

```bash
# 批量分析脚本
cat > analyze_crashes.sh << 'EOF'
#!/bin/bash
for crash in output/*/crashes/id:*; do
    echo "=== 分析 $(basename $crash) ==="
    timeout 30 gdb -batch \\
        -ex "file ./target" \\
        -ex "run < $crash" \\
        -ex "bt 10" \\
        -ex "info registers" \\
        -ex "x/10i \\$rip" \\
        -ex "x/20x \\$rsp" \\
        -ex "quit" \\
        2>&1 | tee "${crash}.analysis"
done
EOF

chmod +x analyze_crashes.sh
./analyze_crashes.sh
```

### 4.3 可利用性评估指标

- **栈溢出特征**：
  - RIP寄存器包含用户控制的数据
  - 栈金丝雀检测触发
  - 栈帧被覆盖

- **堆溢出特征**：
  - malloc/free相关崩溃
  - 堆元数据损坏
  - double free检测

- **控制流劫持**：
  - 指令指针指向非法地址
  - 函数指针被覆盖
  - 返回地址被修改

## 5. 符号执行阶段（源码可用时）

### 5.1 LLVM Bitcode生成

```bash
# 单文件编译
clang -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone source.c -o source.bc

# 多文件项目编译
export CC=clang
export CFLAGS="-emit-llvm -c -g -O0"
make clean && make
llvm-link *.bc -o combined.bc
```

### 5.2 KLEE执行策略

```bash
# 基础符号执行
klee --max-time=3600 --max-memory=2000 source.bc

# 优化配置
klee \\
  --max-time=7200 \\
  --max-memory=4000 \\
  --max-instruction-time=30 \\
  --max-solver-time=30 \\
  --use-forked-solver \\
  --search=random-path \\
  --write-cvcs \\
  --write-cov \\
  source.bc
```

### 5.3 符号执行结果分析

```bash
# 测试用例统计
ls klee-last/*.ktest | wc -l

# 错误分析
cat klee-last/*.err | grep -E "division by zero|memory error|buffer overflow"

# 覆盖率分析
klee-stats klee-last/
```

## 6. 结果整合和报告生成

### 6.1 数据收集

```bash
mkdir -p final_report/{crashes,coverage,symbolic,static}

# 收集关键崩溃（去重后）
cp output/*/crashes/id:* final_report/crashes/

# 收集符号执行错误
cp klee-last/*.err final_report/symbolic/

# 生成覆盖率报告（如有gcov支持）
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory final_report/coverage/
```

### 6.2 威胁评级

| 等级 | 条件 | 建议处理时间 |
|------|------|-------------|
| 关键 | 控制流劫持 + 远程可达 | 24小时内 |
| 高危 | 内存损坏 + 用户输入 | 7天内 |
| 中危 | 拒绝服务 + 输入验证缺失 | 30天内 |
| 低危 | 信息泄露或资源消耗 | 90天内 |

### 6.3 修复建议模板

```markdown
## 漏洞修复建议

### 立即修复（关键/高危）
1. **函数替换**
   - 将 gets() 替换为 fgets()
   - 将 strcpy() 替换为 strncpy() 或 strlcpy()
   - 将 sprintf() 替换为 snprintf()

2. **边界检查**
   - 添加所有数组访问的边界检查
   - 验证所有外部输入的长度和格式

3. **编译选项**
   ```bash
   CFLAGS="-fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIE"
   LDFLAGS="-pie -Wl,-z,relro,-z,now"
   ```

### 长期改进
1. 引入静态分析工具到CI/CD流程
2. 实施定期安全测试
3. 建立漏洞奖励计划
4. 考虑内存安全语言重写关键模块
```

## 常见问题和解决方案

### AFL++相关问题

- **无输出**：检查插桩、种子文件、权限
- **覆盖率低**：优化种子、添加字典、调整策略
- **内存不足**：减少并发实例、优化内存限制

### GDB分析问题

- **分析超时**：增加timeout、简化分析脚本
- **符号缺失**：使用调试版本、保留符号信息
- **地址随机化**：临时禁用ASLR进行分析

### KLEE执行问题

- **内存溢出**：减少内存限制、限制执行路径
- **求解器超时**：调整求解器参数、简化约束
- **路径爆炸**：使用启发式搜索、设置分支限制

这个工作流程应该根据具体的目标程序和分析需求进行调整。重点是保持系统性和可重现性。
