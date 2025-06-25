---
name: crash_analysis
type: knowledge
triggers:
  - crash analysis
  - gdb analysis
  - 崩溃分析
  - exploitability
  - vulnerability analysis
  - 可利用性分析
---

# 专业崩溃分析指南

使用GDB和相关工具进行深度崩溃分析，评估安全漏洞的严重性和可利用性。

## 基础崩溃分析流程

### 1. 崩溃重现和环境准备

```bash
# 验证崩溃的稳定性
for i in {1..5}; do
    echo "测试 $i:"
    timeout 10 ./target < crash_input
    echo "退出代码: $?"
done

# 禁用ASLR以便于分析（临时）
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# 生成核心转储文件
ulimit -c unlimited
echo "core.%p" | sudo tee /proc/sys/kernel/core_pattern
```

### 2. GDB基础分析命令序列

```bash
# 创建标准分析脚本
cat > crash_analysis.gdb << 'EOF'
set pagination off
set confirm off
set print elements 0

# 加载程序和核心转储
file ./target
core-file core.12345
# 或者直接运行
# run < crash_input

# 基础信息收集
info program
info signals
bt full
info registers
info proc mappings

# 内存状态检查
x/20i $rip-40
x/20i $rip
x/40x $rsp-80
x/40x $rbp-40

# 栈帧分析
info frame
info locals
info args

# 查找敏感数据
find &main, +0x1000, 0x41414141
find $rsp-0x1000, $rsp+0x1000, "AAAA"

quit
EOF

gdb -batch -x crash_analysis.gdb 2>&1 | tee crash_report.txt
```

### 3. 自动化批量分析

```bash
#!/bin/bash
# 批量崩溃分析脚本

BINARY="$1"
CRASH_DIR="$2"
OUTPUT_DIR="${3:-analysis_results}"

mkdir -p "$OUTPUT_DIR"

analyze_crash() {
    local crash_file="$1"
    local output_file="$2"
    
    cat > /tmp/gdb_script.txt << 'EOF'
set pagination off
set confirm off
file TARGET_BINARY
run < CRASH_FILE
bt 15
info registers
x/10i $rip-20
x/10i $rip
x/20x $rsp
x/20x $rbp
info proc mappings
quit
EOF
    
    sed -i "s|TARGET_BINARY|$BINARY|g" /tmp/gdb_script.txt
    sed -i "s|CRASH_FILE|$crash_file|g" /tmp/gdb_script.txt
    
    timeout 30 gdb -batch -x /tmp/gdb_script.txt 2>&1 > "$output_file"
    
    # 提取关键信息
    extract_crash_info "$output_file" >> "${output_file}.summary"
}

extract_crash_info() {
    local analysis_file="$1"
    
    echo "=== 崩溃摘要 ==="
    grep "Program received signal" "$analysis_file" || echo "信号: 未知"
    grep "rip.*0x" "$analysis_file" | head -1 || echo "RIP: 未知"
    grep "#0" "$analysis_file" | head -1 || echo "崩溃位置: 未知"
    
    # 检查控制流劫持迹象
    if grep -q "0x[4-6][1-9a-f]" "$analysis_file"; then
        echo "⚠️  疑似控制流劫持"
    fi
    
    # 检查栈溢出迹象  
    if grep -q "stack smashing detected\\|__stack_chk_fail" "$analysis_file"; then
        echo "⚠️  栈保护触发"
    fi
    
    echo ""
}

# 处理所有崩溃文件
for crash in "$CRASH_DIR"/id:*; do
    if [ -f "$crash" ]; then
        basename_crash=$(basename "$crash")
        echo "分析: $basename_crash"
        analyze_crash "$crash" "$OUTPUT_DIR/${basename_crash}.analysis"
    fi
done

# 生成统计报告
generate_summary_report "$OUTPUT_DIR"
```

## 深度漏洞分析技术

### 1. 栈溢出分析

```bash
# 栈溢出模式检测
cat > stack_analysis.gdb << 'EOF'
define analyze_stack_overflow
    set $rsp_val = $rsp
    set $rbp_val = $rbp
    
    echo \\n=== 栈溢出分析 ===\\n
    
    # 检查返回地址是否被覆盖
    x/8x $rbp
    set $ret_addr = *(long*)($rbp + 8)
    printf "返回地址: 0x%lx\\n", $ret_addr
    
    # 检查是否包含用户数据模式
    if ($ret_addr >= 0x4141414140000000 && $ret_addr <= 0x4141414142424242)
        echo "⚠️  返回地址被用户数据覆盖"
    end
    
    # 查找缓冲区起始位置
    set $search_start = $rsp - 0x1000
    set $search_end = $rbp + 0x100
    echo \\n查找缓冲区边界...\\n
    
    # 显示栈内容模式
    echo \\n栈内容分析:\\n
    x/50x $rsp - 0x100
end

file ./target  
run < crash_input
analyze_stack_overflow
quit
EOF

gdb -batch -x stack_analysis.gdb
```

### 2. 堆溢出分析

```bash
# 堆分析脚本
cat > heap_analysis.gdb << 'EOF'
define analyze_heap_corruption
    echo \\n=== 堆损坏分析 ===\\n
    
    # 检查是否在堆相关函数中崩溃
    bt | grep -E "malloc|free|realloc|calloc"
    
    # 显示堆状态
    info proc mappings | grep heap
    
    # 检查malloc_chunk结构
    # (需要libc调试符号)
    
    echo \\n查找堆块元数据...\\n
    # 查找可能的堆块头部
    find 0x555555554000, 0x555555600000, 0x0000000000000021
    
end

file ./target
run < crash_input  
analyze_heap_corruption
quit
EOF
```

### 3. 格式化字符串漏洞分析

```bash
# 格式化字符串分析
cat > format_string_analysis.gdb << 'EOF'
define analyze_format_string
    echo \\n=== 格式化字符串分析 ===\\n
    
    # 检查是否在printf系列函数中
    bt | grep -E "printf|fprintf|sprintf|snprintf|vprintf"
    
    # 分析格式化字符串参数
    info frame
    info args
    
    # 查找栈上的格式化字符串
    find $rsp-0x100, $rsp+0x500, "%"
    
    echo \\n栈内容（查找%格式符）:\\n
    x/50s $rsp
end

file ./target
run < crash_input
analyze_format_string
quit
EOF
```

## 可利用性评估

### 1. 自动化可利用性检查

```bash
#!/bin/bash
# 可利用性评估脚本

assess_exploitability() {
    local crash_file="$1"
    local binary="$2"
    
    echo "=== 可利用性评估: $(basename $crash_file) ==="
    
    # 基础崩溃信息
    local analysis=$(gdb -batch \
        -ex "file $binary" \
        -ex "run < $crash_file" \
        -ex "bt 5" \
        -ex "info registers" \
        -ex "quit" 2>&1)
    
    local score=0
    local details=()
    
    # 控制流劫持检测 (+3分)
    if echo "$analysis" | grep -q "0x[4-6][1-9a-f]"; then
        score=$((score + 3))
        details+=("✓ 控制流劫持可能 (+3)")
    fi
    
    # 栈溢出检测 (+2分)  
    if echo "$analysis" | grep -q "stack smashing\\|__stack_chk_fail"; then
        score=$((score + 2))
        details+=("✓ 栈溢出确认 (+2)")
    fi
    
    # 堆损坏检测 (+2分)
    if echo "$analysis" | grep -q "malloc\\|free\\|heap"; then
        score=$((score + 2))
        details+=("✓ 堆损坏可能 (+2)")
    fi
    
    # 写入访问检测 (+1分)
    if echo "$analysis" | grep -q "SIGSEGV.*writing"; then
        score=$((score + 1))
        details+=("✓ 写入访问违规 (+1)")
    fi
    
    # 确定严重程度
    if [ $score -ge 4 ]; then
        echo "🔴 高可利用性 (分数: $score)"
    elif [ $score -ge 2 ]; then
        echo "🟡 中等可利用性 (分数: $score)"
    else
        echo "🟢 低可利用性 (分数: $score)"
    fi
    
    # 显示详细信息
    for detail in "${details[@]}"; do
        echo "  $detail"
    done
    
    echo ""
}

# 批量评估
for crash in crashes/id:*; do
    assess_exploitability "$crash" "./target"
done
```

### 2. 利用难度评估

```bash
# 利用难度因子评估
evaluate_exploit_difficulty() {
    local binary="$1"
    
    echo "=== 利用难度评估 ==="
    
    # 检查安全缓解措施
    local protections=$(checksec --file="$binary" 2>/dev/null)
    
    if echo "$protections" | grep -q "No canary found"; then
        echo "📉 无栈保护 (难度降低)"
    else
        echo "📈 有栈保护 (难度增加)"
    fi
    
    if echo "$protections" | grep -q "No PIE"; then
        echo "📉 无地址随机化 (难度降低)"  
    else
        echo "📈 有地址随机化 (难度增加)"
    fi
    
    if echo "$protections" | grep -q "No RELRO"; then
        echo "📉 无重定位保护 (难度降低)"
    else
        echo "📈 有重定位保护 (难度增加)"
    fi
    
    # 检查是否为远程服务
    if ldd "$binary" | grep -q "libnet\\|libsocket"; then
        echo "📈 网络服务 (影响面大)"
    fi
    
    # 检查权限
    if [ -u "$binary" ] || [ -g "$binary" ]; then
        echo "📈 提权程序 (影响严重)"
    fi
}
```

## 高级分析技术

### 1. 动态污点分析

```bash
# 使用Intel Pin进行污点分析
cat > taint_analysis.sh << 'EOF'
#!/bin/bash

# 需要Intel Pin工具
PIN_ROOT="/opt/pin"
TAINT_TOOL="$PIN_ROOT/source/tools/TaintTrace/obj-intel64/TaintTrace.so"

if [ ! -f "$TAINT_TOOL" ]; then
    echo "需要构建Intel Pin的TaintTrace工具"
    exit 1
fi

# 运行污点分析
$PIN_ROOT/pin -t $TAINT_TOOL -- ./target < crash_input

# 分析污点传播结果
echo "分析污点传播路径..."
grep -A 5 -B 5 "taint.*rip\\|taint.*pc" pintool.out
EOF
```

### 2. 符号执行辅助分析

```bash
# 结合KLEE进行路径分析
analyze_crash_path() {
    local crash_file="$1"
    
    # 如果有源码，使用KLEE重现路径
    if [ -f "source.bc" ]; then
        echo "使用KLEE分析崩溃路径..."
        
        # 创建KLEE测试用例
        ktest-tool --write-ints crash_input.ktest < "$crash_file"
        
        # 运行KLEE重现路径
        klee --replay-path=crash_input.ktest source.bc
        
        echo "KLEE路径分析完成"
    fi
}
```

### 3. 返回导向编程(ROP)分析

```bash
# 寻找ROP gadgets
find_rop_gadgets() {
    local binary="$1"
    
    echo "=== ROP Gadgets分析 ==="
    
    # 使用ropper寻找gadgets  
    if command -v ropper &> /dev/null; then
        ropper --file "$binary" --search "pop rdi; ret"
        ropper --file "$binary" --search "pop rsi; ret"  
        ropper --file "$binary" --search "pop rdx; ret"
        ropper --file "$binary" --search "syscall"
    else
        echo "ropper工具不可用，使用objdump查找"
        objdump -d "$binary" | grep -A 1 -B 1 "pop.*ret\\|syscall"
    fi
}
```

## 报告生成

### 1. 结构化崩溃报告

```bash
generate_crash_report() {
    local crash_file="$1"
    local binary="$2"
    local output_file="$3"
    
    cat > "$output_file" << EOF
# 崩溃分析报告

## 基础信息
- **崩溃文件**: $(basename $crash_file)
- **目标程序**: $binary  
- **文件大小**: $(stat -c%s $crash_file) bytes
- **分析时间**: $(date)

## 崩溃详情
\`\`\`
$(gdb -batch -ex "file $binary" -ex "run < $crash_file" -ex "bt 10" -ex "info registers" -ex "quit" 2>&1)
\`\`\`

## 可利用性评估
$(assess_exploitability "$crash_file" "$binary")

## 安全缓解措施
\`\`\`
$(checksec --file="$binary" 2>/dev/null || echo "checksec不可用")
\`\`\`

## 修复建议
基于分析结果的具体修复建议...

EOF
}
```

### 2. 批量报告生成

```bash
# 生成综合分析报告
generate_summary_report() {
    local analysis_dir="$1"
    
    cat > "$analysis_dir/SUMMARY.md" << 'EOF'
# 崩溃分析汇总报告

## 统计概览
EOF
    
    echo "- 总崩溃数: $(ls $analysis_dir/*.analysis 2>/dev/null | wc -l)" >> "$analysis_dir/SUMMARY.md"
    echo "- 高危崩溃: $(grep -l "高可利用性" $analysis_dir/*.summary 2>/dev/null | wc -l)" >> "$analysis_dir/SUMMARY.md"
    echo "- 中危崩溃: $(grep -l "中等可利用性" $analysis_dir/*.summary 2>/dev/null | wc -l)" >> "$analysis_dir/SUMMARY.md"
    
    cat >> "$analysis_dir/SUMMARY.md" << 'EOF'

## 关键发现
EOF
    
    # 列出高危崩溃
    grep -l "高可利用性" "$analysis_dir"/*.summary 2>/dev/null | while read file; do
        echo "- $(basename $file .summary)" >> "$analysis_dir/SUMMARY.md"
    done
}
```

这个指南涵盖了专业级的崩溃分析技术，适用于深度安全研究和漏洞评估工作。