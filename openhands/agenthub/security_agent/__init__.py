"""SecurityAgent - 专业安全分析代理

基于OpenHands架构的安全分析工具，集成AFL++、GDB、KLEE等专业安全工具
用于漏洞发现、崩溃分析、符号执行等防御性安全任务。
"""

from openhands.controller.agent import Agent

from .security_agent import SecurityAgent

# 注册SecurityAgent到代理系统
Agent.register('SecurityAgent', SecurityAgent)

__all__ = ['SecurityAgent']
