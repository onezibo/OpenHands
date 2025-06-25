---
name: afl_fuzzing
type: knowledge
triggers:
  - afl
  - fuzzing
  - 模糊测试
  - afl++
  - crash discovery
---

# AFL++高级使用指南

AFL++是一个强大的覆盖引导模糊测试工具，这里提供专业级使用技巧和最佳实践。

## 编译和插桩策略

### 1. 源码插桩（推荐）

```bash
# 最快的插桩方式
export CC=afl-clang-fast
export CXX=afl-clang-fast++
./configure --disable-shared
make clean && make

# LTO模式（Link Time Optimization）- 更好的覆盖率
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_STARTFILES=1
make clean && make

# 比较覆盖（CMPLOG）- 处理复杂比较
export AFL_LLVM_CMPLOG=1
make clean && make target-cmplog
```

### 2. 无源码二进制

```bash
# QEMU模式 - 广泛兼容
afl-fuzz -Q -i input -o output -- ./binary

# Frida模式 - 更快的无源码fuzzing
afl-fuzz -O -i input -o output -- ./binary

# Unicorn模式 - CPU模拟
afl-fuzz -U -i input -o output -- ./binary
```

## 高级Fuzzing技术

### 1. 种子语料库优化

```bash
# 收集高质量种子
mkdir corpus_raw
# 从样本文件、测试用例、协议规范等收集种子

# 语料库最小化 - 移除冗余种子
afl-cmin -i corpus_raw -o corpus_min -- ./target @@

# 单个文件最小化 - 减少测试用例大小
afl-tmin -i large_seed -o small_seed -- ./target @@

# 语料库去重
afl-showmap -o /dev/null -- ./target < seed1 > map1
afl-showmap -o /dev/null -- ./target < seed2 > map2
# 比较map1和map2确定唯一性
```

### 2. 字典使用策略

```bash
# 使用预定义字典
afl-fuzz -i input -o output -x dict.txt -- ./target @@

# 自动生成字典
afl-fuzz -i input -o output -D -- ./target @@

# 从源码自动提取字典
grep -r "strcmp\\|memcmp\\|strstr" source/ | \
  sed -E 's/.*"([^"]+)".*/\\1/' | sort -u > auto_dict.txt

# JSON特定字典示例
cat > json.dict << 'EOF'
"{"
"}"
"["
"]"
":"
","
"true"
"false"
"null"
"string"
"number"
EOF
```

### 3. 并行Fuzzing最佳实践

```bash
# CPU核心分配策略（8核示例）
# 1个主fuzzer（确定性）
afl-fuzz -i input -o output -M main -- ./target @@

# 2个从fuzzer（随机变异）
afl-fuzz -i input -o output -S slave01 -- ./target @@
afl-fuzz -i input -o output -S slave02 -- ./target @@

# 1个确定性fuzzer
afl-fuzz -i input -o output -S determ01 -d -- ./target @@

# 2个探索fuzzer（新路径优先）
afl-fuzz -i input -o output -S explore01 -p explore -- ./target @@
afl-fuzz -i input -o output -S explore02 -p explore -- ./target @@

# 1个CMPLOG fuzzer（如果编译了cmplog版本）
afl-fuzz -i input -o output -S cmplog01 -c ./target-cmplog -- ./target @@

# 1个MOpt fuzzer（机器学习优化）
afl-fuzz -i input -o output -S mopt01 -L 0 -- ./target @@
```

### 4. 性能优化配置

```bash
# 系统配置优化
sudo afl-system-config

# 环境变量优化
export AFL_TMPDIR=/dev/shm        # 使用内存文件系统
export AFL_SKIP_CPUFREQ=1         # 跳过CPU频率检查
export AFL_NO_AFFINITY=1          # 禁用CPU亲和性
export AFL_DISABLE_TRIM=1         # 禁用文件裁剪（加速）

# 持久模式 - 显著提升性能
# 需要修改目标程序源码
__AFL_FUZZ_INIT();
while (__AFL_LOOP(1000)) {
    // 重置程序状态
    reset_state();
    // 处理输入
    process_input();
}
```

## 专业分析技巧

### 1. 覆盖率分析

```bash
# 生成覆盖率地图
afl-showmap -o coverage.map -- ./target < input_file

# 比较两个输入的覆盖率差异
afl-showmap -o map1 -- ./target < input1
afl-showmap -o map2 -- ./target < input2
diff map1 map2

# 可视化覆盖率
afl-plot output plot_dir
# 在浏览器中打开 plot_dir/index.html

# 实时监控
afl-whatsup -s output  # 简洁模式
afl-whatsup output     # 详细模式
```

### 2. 崩溃分析流程

```bash
# 崩溃收集和去重
afl-collect -r output -- ./target @@

# 崩溃最小化
mkdir minimized_crashes
for crash in output/*/crashes/id:*; do
    output_name="minimized_$(basename $crash)"
    afl-tmin -i "$crash" -o "minimized_crashes/$output_name" -- ./target @@
done

# 崩溃分类脚本
cat > classify_crashes.sh << 'EOF'
#!/bin/bash
mkdir -p crash_classes/{segfault,abort,bus_error,other}

for crash in output/*/crashes/id:*; do
    timeout 10 gdb -batch \
        -ex "run < $crash" \
        -ex "info signal" \
        -ex "quit" \
        ./target 2>&1 | \
    if grep -q "SIGSEGV"; then
        cp "$crash" crash_classes/segfault/
    elif grep -q "SIGABRT"; then
        cp "$crash" crash_classes/abort/
    elif grep -q "SIGBUS"; then
        cp "$crash" crash_classes/bus_error/
    else
        cp "$crash" crash_classes/other/
    fi
done
EOF
```

### 3. 特殊场景处理

#### 网络程序Fuzzing

```bash
# 使用AFL网络代理
afl-network-server 8080 &
afl-fuzz -i input -o output -- afl-network-client 8080

# 使用preeny库转换网络程序为标准输入
LD_PRELOAD=desock.so afl-fuzz -i input -o output -- ./network_server
```

#### 多线程程序

```bash
# 禁用fork服务器（可能影响性能）
export AFL_NO_FORKSRV=1
afl-fuzz -i input -o output -- ./multithreaded_app

# 使用持久模式处理多线程
# 在代码中正确处理线程清理
```

#### 复杂输入格式

```bash
# 结构化输入fuzzing（如图片、文档）
# 使用自定义mutator
export AFL_CUSTOM_MUTATOR_LIBRARY=./custom_mutator.so
afl-fuzz -i input -o output -- ./target @@

# 语法感知fuzzing
# 使用grammar-based mutator
# 参考Grammarinator、FormatFuzzer等工具
```

## 高级配置选项

### 1. 环境变量详解

```bash
# 内存限制（MB）
export AFL_MEM_LIMIT=200

# 超时设置（毫秒）
export AFL_TIMEOUT=5000

# 跳过确定性阶段
export AFL_SKIP_DETERMIN=1

# 崩溃模式（继续执行即使发现崩溃）
export AFL_CRASH_EXITCODE=1

# 自定义变异比例
export AFL_MUTATOR_RATIO=50

# 启用MOpt（机器学习优化）
export AFL_USE_MOPT=1
```

### 2. 命令行参数组合

```bash
# 内存高效模式
afl-fuzz -m 50 -t 1000 -i input -o output -- ./target @@

# 快速发现模式
afl-fuzz -d -n -i input -o output -- ./target @@

# 深度探索模式
afl-fuzz -p explore -L 10 -i input -o output -- ./target @@

# 最大兼容模式
afl-fuzz -Q -m none -t 10000 -i input -o output -- ./target @@
```

## 故障排除指南

### 常见错误和解决方案

```bash
# 错误: "No instrumentation detected"
# 解决: 确保使用afl-gcc/afl-clang编译
export CC=afl-clang-fast && make clean && make

# 错误: "Fork server handshake failed"
# 解决1: 检查程序是否正常启动
./target < input/seed1
# 解决2: 增加内存限制
afl-fuzz -m none -i input -o output -- ./target @@

# 错误: "Suboptimal CPU frequency scaling"
# 解决: 设置CPU频率或跳过检查
export AFL_SKIP_CPUFREQ=1

# 错误: "Unable to create shared memory"
# 解决: 调整系统共享内存限制
sudo sysctl -w kernel.shmmax=67108864
sudo sysctl -w kernel.shmall=32768
```

### 性能调优检查表

- [ ] 使用最新版本的AFL++
- [ ] 启用编译器优化（但保持插桩）
- [ ] 使用内存文件系统（tmpfs）
- [ ] 正确配置并行实例数量
- [ ] 优化种子语料库质量
- [ ] 使用适当的字典文件
- [ ] 配置系统内核参数
- [ ] 监控系统资源使用情况

### 质量评估指标

```bash
# 执行速度（目标: >1000 exec/sec）
grep "exec speed" output/*/fuzzer_stats

# 路径发现（持续增长为好）
grep "paths_found" output/*/fuzzer_stats

# 崩溃发现率
find output -name "id:*" -path "*/crashes/*" | wc -l

# 覆盖率增长曲线
afl-plot output plot && firefox plot/index.html
```

## 集成和自动化

### CI/CD集成示例

```bash
#!/bin/bash
# .github/workflows/fuzzing.yml 的一部分

# 构建插桩版本
export CC=afl-clang-fast
make clean && make

# 运行短时间fuzzing测试
timeout 300 afl-fuzz -i seeds -o fuzz_results -- ./target @@

# 检查是否发现新崩溃
if [ -d "fuzz_results/default/crashes" ] && [ "$(ls -A fuzz_results/default/crashes)" ]; then
    echo "发现新崩溃，构建失败"
    exit 1
fi
```

### 持续fuzzing部署

```bash
# Docker容器化fuzzing
docker run -d --name continuous_fuzzing \
  -v $(pwd):/workspace \
  -v /dev/shm:/dev/shm \
  afl-docker:latest \
  afl-fuzz -i /workspace/seeds -o /workspace/results -- /workspace/target @@

# 定期收集结果
crontab -e
# 每小时收集一次崩溃
0 * * * * /path/to/collect_crashes.sh
```

这个指南涵盖了AFL++的高级使用技巧，适合专业的安全分析工作。记住要根据具体的目标程序调整策略。