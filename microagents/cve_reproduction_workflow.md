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

这是一个标准化的CVE漏洞复现流程，专注于配置漏洞环境并成功触发漏洞。

## 🎯 核心原则

1. **实际环境配置**：根据exploit信息配置精确的漏洞环境
2. **直接漏洞触发**：使用具体的触发条件来执行漏洞复现
3. **验证导向**：通过crash分析和调试工具验证复现成功
4. **简化高效**：避免过度分析，专注于实际的复现操作

## 📋 简化CVE复现流程

### 阶段1：CVE识别与NVD分析

#### 1.1 识别CVE并获取NVD页面
```bash
# 从任务中识别CVE ID
CVE_ID="CVE-YYYY-NNNNN"
NVD_URL="https://nvd.nist.gov/vuln/detail/${CVE_ID}"
```

#### 1.2 使用Browser Tool分析NVD页面
```python
# 分析NVD页面，重点关注exploit标记的链接
# 使用Browser Tool导航到NVD页面并获取内容
goto(NVD_URL)
noop()  # 获取页面内容，重点识别标记为'Exploit'的链接
# 从页面内容中提取exploit链接进行后续分析
```

### 阶段2：Exploit信息提取

#### 2.1 分析exploit标记的链接
```python
# 对找到的exploit链接进行分析
for exploit_link in exploit_links:
    # 使用Browser Tool导航到exploit链接并获取内容
    goto(exploit_link)
    noop()  # 获取页面内容，提取环境配置、漏洞版本、编译选项、触发输入、测试命令等复现所需的具体信息
```

#### 2.2 重点提取的信息

从exploit链接中重点提取：
- **漏洞版本**：受影响的软件版本
- **编译选项**：构建漏洞版本所需的编译参数
- **触发输入**：具体的输入数据或参数
- **测试命令**：执行漏洞复现的具体命令
- **环境要求**：操作系统、依赖库等环境配置

### 阶段3：环境配置与漏洞触发

#### 3.1 配置漏洞环境
```bash
# 根据exploit信息配置环境
export CC="gcc"  # 或根据exploit要求的编译器
export CFLAGS="-fsanitize=address -g"  # 使用ASAN检测内存错误

# 安装或构建漏洞版本
# 方法1：安装特定版本的包
apt-get install package=vulnerable-version

# 方法2：从源码构建漏洞版本
git clone repository-url
git checkout vulnerable-commit
./configure && make
```

#### 3.2 执行漏洞触发
```bash
# 使用从exploit中提取的具体触发命令
./vulnerable-binary [specific-parameters]

# 或使用具体的触发输入
echo "trigger-input-data" | ./vulnerable-binary

# 使用文件输入触发
echo "trigger-data" > trigger-file
./vulnerable-binary trigger-file
```

#### 3.3 验证复现成功
```bash
# 检查是否产生崩溃
if [ $? -ne 0 ]; then
    echo "漏洞复现成功 - 程序崩溃"
fi

# 使用GDB获取详细的崩溃信息
gdb -batch \
    -ex "file ./vulnerable-binary" \
    -ex "run [parameters]" \
    -ex "bt" \
    -ex "quit"
```

### 阶段4：AFL++增强测试（可选）

#### 4.1 使用AFL++进行进一步测试
```bash
# 使用触发输入作为AFL++种子
mkdir seeds
echo "original-trigger-input" > seeds/exploit_seed

# 启动AFL++模糊测试
afl-fuzz -i seeds -o output -- ./vulnerable-binary @@
```

## 🔧 简化工具使用指南

### Browser Tool最佳实践
- **NVD页面分析**：使用goto()导航到NVD页面，然后noop()获取页面内容，重点识别标记为'Exploit'的链接
- **Exploit链接分析**：使用goto()导航到exploit链接，然后noop()获取页面内容，提取环境配置、漏洞版本、编译选项、触发输入、测试命令
- **关注实际操作**：优先提取可操作的配置信息，而非理论描述

### 复现验证标准
- **环境匹配**：成功配置与exploit描述一致的环境
- **触发成功**：使用特定输入成功触发漏洞
- **崩溃验证**：通过调试工具确认崩溃现象

## ⚠️ 常见问题与解决方案

### 环境配置问题
- **版本不匹配**：仔细确认exploit中提到的确切版本
- **编译失败**：检查编译选项和依赖库
- **依赖缺失**：根据exploit信息安装所需依赖

### 触发失败问题
- **输入格式错误**：检查触发输入的确切格式
- **参数错误**：确认命令行参数的正确性
- **环境变量**：检查是否需要特定的环境变量设置

## 📊 成功指标

一个成功的CVE复现应该达到：
1. **环境配置成功**：按照exploit要求配置好漏洞环境
2. **漏洞触发成功**：使用特定输入成功触发漏洞
3. **崩溃验证**：通过工具确认漏洞现象
4. **可重复性**：能够多次重现相同的漏洞

这个简化的工作流程确保SecurityAgent专注于实际的CVE复现操作，避免在信息分析上花费过多时间。
