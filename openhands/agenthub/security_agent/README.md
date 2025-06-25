# SecurityAgent

SecurityAgent是基于OpenHands架构的专业安全分析代理，专门用于防御性安全分析任务。

## 功能特性

- **模糊测试 (Fuzzing)**: 集成AFL++进行智能模糊测试
- **崩溃分析**: 使用GDB进行深度崩溃分析和可利用性评估  
- **符号执行**: 基于KLEE的符号执行分析
- **静态分析**: 二进制文件安全特性检查
- **智能报告**: 自动生成详细的安全分析报告

## 架构设计

```
SecurityAgent/
├── security_agent.py      # 主要Agent类（继承自CodeActAgent）
├── prompts/               # 安全分析专用提示词模板
│   ├── system_prompt.j2
│   ├── user_prompt.j2  
│   └── ...
└── README.md             # 本文件
```

## Agent Skills集成

SecurityAgent通过Agent Skills系统调用专业安全工具：

- `afl_skills.py` - AFL++模糊测试功能
- `gdb_skills.py` - GDB调试和崩溃分析
- `klee_skills.py` - KLEE符号执行
- `analysis_skills.py` - 通用安全分析工具

## 使用方式

```python
# 通过CLI启动
openhands --agent SecurityAgent --task "分析 /path/to/binary 的安全性"

# 或通过API
from openhands import SecurityAgent
agent = SecurityAgent(llm, config)
result = agent.run("全面分析目标程序的安全漏洞")
```

## 设计原则

1. **最小修改**: 充分利用OpenHands现有架构
2. **模块化**: 各安全工具独立封装，易于维护
3. **智能分析**: 结合LLM推理能力进行专业安全分析
4. **防御导向**: 专注于漏洞发现和安全评估