# SecurityAgent Docker Runtime Environment

这个目录包含SecurityAgent的Docker运行时环境配置，为OpenHands提供专业的安全分析工具支持。

## 概述

SecurityAgent扩展了标准的OpenHands运行时环境，添加了以下安全分析工具：

- **AFL++**: 先进的覆盖引导模糊测试工具
- **GDB**: GNU调试器，配备pwndbg等安全分析插件
- **KLEE**: 符号执行引擎（基础配置）
- **Binary Analysis Tools**: checksec, objdump, readelf, strings等
- **Python Security Libraries**: pwntools, capstone, keystone等

## 快速开始

### 1. 构建SecurityAgent运行时镜像

```bash
cd containers/security
./build-security-runtime.sh
```

### 2. 验证工具安装

```bash
docker run --rm openhands-security:latest check-security-tools
```

### 3. 在OpenHands中使用

```bash
# 设置运行时镜像
export RUNTIME_IMAGE=openhands-security:latest

# 启动SecurityAgent
openhands --agent SecurityAgent --runtime docker
```

## 文件说明

- `Dockerfile.security-extension`: SecurityAgent的Docker扩展配置
- `build-security-runtime.sh`: 自动化构建脚本
- `README.md`: 本说明文档

## 包含的安全工具

### 模糊测试工具
- `afl-fuzz`: 主要的模糊测试引擎
- `afl-cmin`: 语料库最小化工具
- `afl-tmin`: 测试用例最小化工具
- `afl-whatsup`: 模糊测试状态监控
- `afl-plot`: 模糊测试结果可视化

### 调试和分析工具
- `gdb`: GNU调试器
- `pwndbg`: GDB的高级安全分析插件
- `checksec`: 二进制安全特性检查
- `objdump`: 目标文件反汇编
- `readelf`: ELF文件分析
- `strings`: 字符串提取
- `file`: 文件类型识别

### 符号执行和静态分析
- `clang`: LLVM编译器（用于生成bitcode）
- `klee`: 符号执行引擎（基础配置）
- `radare2`: 逆向工程框架

### Python安全库
- `pwntools`: 漏洞利用开发框架
- `capstone`: 反汇编引擎
- `keystone`: 汇编器引擎
- `unicorn`: CPU模拟器引擎

## 使用示例

### 基本安全扫描

```bash
# 启动容器
docker run -it --rm -v $(pwd):/workspace openhands-security:latest

# 在容器内进行快速安全扫描
quick-security-scan /path/to/binary

# 详细的二进制分析
checksec --file=/path/to/binary
objdump -T /path/to/binary | grep -E "gets|strcpy"
```

### 在OpenHands中使用SecurityAgent

```python
# 启动SecurityAgent进行安全分析
user_input = "分析 /workspace/target_binary 的安全性，包括模糊测试和崩溃分析"

# SecurityAgent将自动：
# 1. 检查二进制安全特性
# 2. 识别危险函数使用
# 3. 执行AFL++模糊测试
# 4. 分析发现的崩溃
# 5. 生成详细的安全报告
```

### 高级分析工作流

```bash
# 1. 准备分析环境
mkdir -p /workspace/security/{fuzzing,crashes,reports}

# 2. 基础安全检查
checksec --file=target_binary
objdump -T target_binary

# 3. 模糊测试
echo "test" > /workspace/security/fuzzing/seed1
afl-fuzz -i /workspace/security/fuzzing -o /workspace/security/fuzzing/output -- ./target_binary @@

# 4. 崩溃分析
gdb -batch -ex "run < crash_file" -ex "bt" ./target_binary

# 5. 符号执行（如有源码）
clang -emit-llvm -c -g -O0 source.c -o source.bc
klee source.bc
```

## 环境变量

以下环境变量可用于配置SecurityAgent行为：

- `AFL_SKIP_CPUFREQ=1`: 跳过CPU频率检查
- `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`: 忽略崩溃检查警告
- `AFL_TMPDIR`: AFL++临时目录（默认为/tmp）
- `AFL_TIMEOUT`: AFL++超时设置（默认60秒）

## 安全注意事项

1. **隔离环境**: 始终在隔离的容器环境中进行安全分析
2. **资源限制**: 模糊测试可能消耗大量CPU和内存资源
3. **时间控制**: 使用timeout命令限制长时间运行的分析任务
4. **敏感数据**: 不要在安全分析中包含生产环境的敏感数据

## 故障排除

### 常见问题

1. **AFL++启动失败**
   - 检查目标程序是否正确插桩
   - 确认输入种子文件存在且有效
   - 验证内存和CPU限制设置

2. **GDB分析超时**
   - 增加timeout时间限制
   - 检查是否存在死循环或无限等待

3. **工具不可用**
   - 运行 `check-security-tools` 验证安装
   - 重新构建镜像确保所有工具正确安装

### 性能优化

1. **使用RAM磁盘**
   ```bash
   export AFL_TMPDIR=/dev/shm
   ```

2. **并行分析**
   ```bash
   # 多核模糊测试
   afl-fuzz -M fuzzer01 ...  # 主实例
   afl-fuzz -S fuzzer02 ...  # 从实例
   ```

3. **资源监控**
   ```bash
   # 监控系统资源使用
   docker stats openhands-security
   ```

## 扩展和自定义

### 添加新的安全工具

1. 修改 `Dockerfile.security-extension`
2. 添加工具安装命令
3. 更新 `check-security-tools` 脚本
4. 重新构建镜像

### 自定义配置

可以通过环境变量或卷挂载的方式自定义工具配置：

```bash
docker run -v $(pwd)/custom-config:/config openhands-security:latest
```

## 许可证和致谢

- AFL++: Apache License 2.0
- GDB: GPL v3
- pwndbg: MIT License
- KLEE: NCSA License
- pwntools: MIT License

本SecurityAgent扩展基于OpenHands项目，遵循其开源许可证。