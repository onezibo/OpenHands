---
name: cve_reproduction_workflow
type: knowledge
triggers:
  - CVE reproduction
  - CVE复现
  - exploit analysis
  - vulnerability reproduction
  - 漏洞复现
  - exploit链接分析
---

# CVE漏洞复现通用工作流程

这是一个标准化的CVE漏洞复现流程，专注于从exploit链接中提取关键信息并指导精确复现。

## 🎯 核心原则

1. **基于实际exploit信息**：优先分析CVE页面中标记为"exploit"的链接
2. **信息驱动复现**：从exploit中提取具体的触发条件、测试用例、环境要求
3. **通用流程适配**：同一套流程适用于不同类型的CVE和exploit源头
4. **工具链集成**：充分利用WebFetch、AFL++、GDB等工具进行分析

## 📋 标准CVE复现流程

### 阶段1：CVE信息收集与exploit链接识别

#### 1.1 获取CVE基础信息
```bash
# 从CVE页面提取关键信息
echo "CVE ID: CVE-YYYY-NNNNN"
echo "CVSS评分: [从页面获取]"
echo "漏洞类型: [CWE分类]"
echo "影响组件: [软件/库名称和版本]"
```

#### 1.2 识别exploit链接
CVE页面中需要重点关注的链接类型：
- **带"exploit"标记的链接**（最高优先级）
- **Mailing list讨论**（通常包含技术细节）
- **Bug report链接**（可能包含复现步骤）
- **GitHub/GitLab commit**（包含补丁和测试用例）
- **Security advisories**（官方分析报告）

### 阶段2：Exploit链接深度分析

#### 2.1 使用WebFetch分析exploit链接
```python
# 对每个重要链接进行内容分析
for link in exploit_links:
    content = WebFetch(url=link, prompt="提取CVE相关的技术细节、测试用例、触发条件、复现步骤")
    print(f"链接: {link}")
    print(f"内容摘要: {content}")
```

#### 2.2 不同类型exploit源头的信息提取重点

**A. Mailing List讨论**
- 漏洞发现者的原始报告
- 技术讨论中的触发条件
- 社区提供的测试用例
- 修复建议和补丁讨论

**B. Bug Report**
- 具体的复现步骤
- 环境配置要求
- 编译选项和依赖
- 测试命令和参数

**C. GitHub Commit/Patch**
- 代码层面的修复内容
- 测试用例的具体实现
- 编译和构建指令
- 漏洞函数的具体位置

**D. Security Advisory**
- 官方的漏洞描述
- 影响范围和严重程度
- 推荐的缓解措施
- 官方测试方法

#### 2.3 关键信息提取清单

从exploit分析中需要提取的关键信息：

```markdown
**环境要求**:
- 操作系统版本
- 编译器版本和选项
- 依赖库版本
- 特殊配置要求

**触发条件**:
- 具体的输入数据（数值、字符串、文件内容）
- 函数调用参数
- 运行时参数
- 环境变量设置

**测试用例**:
- 命令行执行方式
- 输入文件内容
- 预期的崩溃现象
- 调试工具使用方法

**技术细节**:
- 漏洞函数名称和位置
- 内存错误类型（栈溢出、堆溢出等）
- 根本原因分析
- 修复方案解释
```

### 阶段3：复现环境构建

#### 3.1 基于exploit信息配置环境
```bash
# 根据提取的信息设置编译环境
export CC="[从exploit中获取的编译器]"
export CFLAGS="[从exploit中获取的编译选项，如-fsanitize=address]"
export LDFLAGS="[链接选项]"

# 安装特定版本的组件
apt-get install [specific-package=version]
# 或从源码编译vulnerable版本
git clone [repository]
git checkout [vulnerable-commit]
```

#### 3.2 构建测试程序
```bash
# 基于exploit信息的构建步骤
./configure [configuration-options]
make clean && make [build-targets]

# 验证构建结果
file target-binary
checksec --file=target-binary
```

### 阶段4：执行复现测试

#### 4.1 精确复现测试
```bash
# 使用从exploit中提取的确切命令
[extracted-command-from-exploit]

# 或使用提取的测试用例
echo "[extracted-test-input]" > test_input
./target-binary [extracted-parameters] < test_input
```

#### 4.2 使用调试工具验证
```bash
# 使用AddressSanitizer（如exploit中建议）
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0"
./target-binary [parameters]

# 使用GDB分析崩溃
gdb -batch \
    -ex "file ./target-binary" \
    -ex "run [parameters]" \
    -ex "bt" \
    -ex "info registers" \
    -ex "quit"
```

### 阶段5：AFL++模糊测试增强

#### 5.1 基于exploit信息优化fuzzing
```bash
# 使用从exploit中提取的测试用例作为种子
mkdir fuzzing_seeds
echo "[extracted-trigger-input]" > fuzzing_seeds/exploit_seed

# 根据漏洞类型选择合适的fuzzing策略
if [heap-overflow]; then
    # 堆溢出专用配置
    afl-fuzz -i fuzzing_seeds -o output -m none -- ./target @@
elif [format-string]; then
    # 格式字符串漏洞配置
    afl-fuzz -i fuzzing_seeds -o output -t 5000 -- ./target @@
else
    # 通用配置
    afl-fuzz -i fuzzing_seeds -o output -- ./target @@
fi
```

## 🔧 工具使用指南

### WebFetch最佳实践
- 针对每种类型的链接使用专门的提取prompt
- 优先提取技术细节而非背景信息
- 关注数值、命令、配置等具体信息

### exploit信息提取技巧
- 在mailing list中寻找"reproduce"、"test case"、"trigger"等关键词
- 在bug report中重点关注"Steps to Reproduce"部分
- 在代码commit中分析测试用例的具体实现
- 关注编译选项，特别是sanitizer相关配置

### 复现验证标准
- 能够重现exploit中描述的确切现象
- 使用相同的调试工具得到相似的输出
- 验证漏洞的根本原因与exploit描述一致

## ⚠️ 常见问题与解决方案

### 环境构建问题
- **依赖版本冲突**：使用容器隔离或虚拟环境
- **编译失败**：检查exploit中的具体编译选项
- **版本不匹配**：确保使用exploit中指定的确切版本

### 复现失败问题
- **输入格式错误**：仔细检查exploit中的输入格式
- **环境差异**：对比exploit中的环境要求
- **时序问题**：某些漏洞可能需要特定的执行时序

### 分析工具问题
- **AddressSanitizer未检测**：验证编译选项和运行时配置
- **GDB无法调试**：检查符号表和调试信息
- **AFL++无法启动**：验证目标程序和输入格式

## 📊 成功指标

一个成功的CVE复现应该达到：
1. **精确复现**：能重现exploit中描述的确切现象
2. **技术理解**：理解漏洞的根本原因和触发机制
3. **工具验证**：使用多种工具验证漏洞的存在和特征
4. **知识提取**：从复现过程中学习到有价值的安全分析方法

这个工作流程确保SecurityAgent能够系统性地处理任何CVE的复现任务，而无需为特定漏洞类型预设详细步骤。