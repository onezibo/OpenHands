"""SecurityAgent - 专业安全分析代理

继承自CodeActAgent，专门用于安全分析任务，集成AFL++、GDB、KLEE等安全工具。
"""

import os
from typing import TYPE_CHECKING, Optional, Dict, Any
import threading
import time

if TYPE_CHECKING:
    from openhands.core.config import AgentConfig
    from openhands.llm.llm import LLM

from openhands.agenthub.codeact_agent.codeact_agent import CodeActAgent
from openhands.runtime.plugins.agent_skills.security.afl_manager import (
    AFLProcessManager,
    AFLFuzzingState,
    AFLStats
)
from openhands.core.logger import openhands_logger as logger
from openhands.runtime.plugins import (
    AgentSkillsRequirement,
    JupyterRequirement,
    PluginRequirement,
)
from openhands.utils.prompt import PromptManager


class SecurityAgent(CodeActAgent):
    """安全分析代理，继承CodeActAgent的所有能力，专门用于安全分析任务"""
    
    VERSION = '1.0'
    
    # 扩展sandbox plugins以包含安全分析工具
    sandbox_plugins: list[PluginRequirement] = [
        AgentSkillsRequirement(),  # 包含安全分析skills
        JupyterRequirement(),      # 保持Jupyter支持用于数据分析
    ]
    
    def __init__(self, llm: 'LLM', config: 'AgentConfig') -> None:
        """初始化SecurityAgent
        
        Args:
            llm: 大语言模型实例
            config: Agent配置
        """
        # 先初始化SecurityAgent特有属性，避免在父类reset()调用时出现AttributeError
        # 延迟工具检测，避免在运行时环境未准备好时检测
        self._security_tools_available: dict[str, bool] | None = None
        self._tools_check_attempted = False
        
        # AFL++进程管理器
        self._afl_manager: Optional[AFLProcessManager] = None
        self._afl_state_history: list[str] = []  # 状态历史，用于生成不同的消息
        self._last_progress_time = 0
        self._progress_lock = threading.Lock()
        
        # 然后调用父类初始化
        super().__init__(llm, config)
        
        # 记录SecurityAgent特定的初始化信息
        logger.info("SecurityAgent初始化完成，已集成安全分析工具支持")
        
    def _check_security_tools(self) -> dict[str, bool]:
        """检查可用的安全工具 - 主机环境检测版本（fallback）
        
        注意：这个方法在主机环境中执行，可能检测不到容器中的工具。
        建议在运行时环境准备好后调用refresh_security_tools_status()重新检测。
        
        Returns:
            dict: 各安全工具的可用状态
        """
        import subprocess
        import concurrent.futures
        import time
        
        start_time = time.time()
        
        def check_single_tool(tool_info: tuple[str, str]) -> tuple[str, bool]:
            """检查单个工具是否可用"""
            tool_name, command = tool_info
            try:
                result = subprocess.run(['which', command], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=2)  # 降低超时时间
                return tool_name, result.returncode == 0
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                return tool_name, False
        
        # 定义要检查的工具列表 (tool_name, command)
        tools_to_check = [
            ('afl++', 'afl-fuzz'),
            ('gdb', 'gdb'),
            ('klee', 'klee'),
            ('checksec', 'checksec'),
            ('objdump', 'objdump'),
            ('clang', 'clang'),
            ('file', 'file'),
            ('strings', 'strings'),
            ('radare2', 'radare2'),
        ]
        
        # 并行检查所有工具
        tools_status = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # 提交所有检查任务
            future_to_tool = {
                executor.submit(check_single_tool, tool_info): tool_info[0] 
                for tool_info in tools_to_check
            }
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_tool):
                try:
                    tool_name, available = future.result(timeout=3)
                    tools_status[tool_name] = available
                except concurrent.futures.TimeoutError:
                    tool_name = future_to_tool[future]
                    tools_status[tool_name] = False
                    logger.warning(f"工具检测超时: {tool_name}")
                except Exception as e:
                    tool_name = future_to_tool[future]
                    tools_status[tool_name] = False
                    logger.warning(f"工具检测异常: {tool_name} - {e}")
        
        # 记录工具可用性状态和性能信息
        check_time = time.time() - start_time
        available_tools = [tool for tool, available in tools_status.items() if available]
        unavailable_tools = [tool for tool, available in tools_status.items() if not available]
        
        logger.info(f"SecurityAgent工具检测完成 (耗时: {check_time:.2f}s, 主机环境)")
        if available_tools:
            logger.info(f"SecurityAgent检测到可用的安全工具: {', '.join(available_tools)}")
        if unavailable_tools:
            logger.warning(f"SecurityAgent检测到不可用的工具: {', '.join(unavailable_tools)}")
            logger.warning("提示：这是主机环境检测结果。请确保使用openhands-security:latest镜像以获得完整功能")
            
        return tools_status
    
    def get_security_tools_status(self) -> dict[str, bool]:
        """获取安全工具可用状态，首次调用时进行检测
        
        Returns:
            dict: 各安全工具的可用状态
        """
        if self._security_tools_available is None and not self._tools_check_attempted:
            # 首次检测工具
            self._tools_check_attempted = True
            logger.info("SecurityAgent首次检测安全工具状态...")
            self._security_tools_available = self._check_security_tools()
        elif self._security_tools_available is None:
            # 检测已尝试但失败，返回空状态
            logger.warning("SecurityAgent工具检测尚未完成或失败，返回默认状态")
            return {}
        
        return self._security_tools_available
    
    def refresh_security_tools_status(self) -> dict[str, bool]:
        """刷新安全工具可用状态，强制重新检测
        
        Returns:
            dict: 更新后的各安全工具可用状态
        """
        logger.info("SecurityAgent强制刷新安全工具状态...")
        self._security_tools_available = self._check_security_tools()
        self._tools_check_attempted = True
        return self._security_tools_available
    
    @property
    def prompt_manager(self) -> PromptManager:
        """重写prompt管理器以包含安全分析相关提示词"""
        if self._prompt_manager is None:
            self._prompt_manager = PromptManager(
                prompt_dir=os.path.join(os.path.dirname(__file__), 'prompts'),
                system_prompt_filename=self.config.system_prompt_filename,
            )
            
        return self._prompt_manager
    
    def start_afl_fuzzing(self, 
                          target_binary: str,
                          input_dir: str,
                          output_dir: str,
                          timeout: int = 600,
                          additional_args: list[str] = None) -> bool:
        """启动AFL++模糊测试（智能管理版本）
        
        Args:
            target_binary: 目标二进制文件路径
            input_dir: 输入语料库目录
            output_dir: 输出目录
            timeout: 超时时间（秒）
            additional_args: 额外AFL++参数
            
        Returns:
            bool: 启动是否成功
        """
        if self._afl_manager and self._afl_manager.process:
            logger.warning("AFL++进程已在运行中")
            return False
        
        try:
            # 创建AFL++管理器
            self._afl_manager = AFLProcessManager(
                output_dir=output_dir,
                target_binary=target_binary,
                input_dir=input_dir,
                timeout=timeout
            )
            
            # 设置回调函数
            self._afl_manager.on_state_change = self._on_afl_state_change
            self._afl_manager.on_crash_found = self._on_afl_crash_found
            self._afl_manager.on_progress_update = self._on_afl_progress_update
            
            # 启动模糊测试
            success = self._afl_manager.start_fuzzing(additional_args)
            
            if success:
                logger.info("AFL++智能模糊测试启动成功")
                # 清空状态历史
                with self._progress_lock:
                    self._afl_state_history.clear()
                    self._last_progress_time = time.time()
            else:
                logger.error("AFL++智能模糊测试启动失败")
                self._afl_manager = None
            
            return success
            
        except Exception as e:
            logger.error(f"启动AFL++智能模糊测试时出错: {e}")
            self._afl_manager = None
            return False
    
    def _on_afl_state_change(self, state: AFLFuzzingState, stats: AFLStats):
        """AFL++状态变化回调"""
        with self._progress_lock:
            state_msg = f"状态变更: {state.value}"
            self._afl_state_history.append(state_msg)
            logger.info(f"AFL++{state_msg}")
    
    def _on_afl_crash_found(self, crash_count: int):
        """AFL++发现崩溃回调"""
        with self._progress_lock:
            crash_msg = f"发现崩溃: {crash_count}个"
            self._afl_state_history.append(crash_msg)
            logger.info(f"AFL++{crash_msg}")
    
    def _on_afl_progress_update(self, stats: AFLStats):
        """AFL++进度更新回调"""
        with self._progress_lock:
            current_time = time.time()
            # 每30秒记录一次进度，避免频繁更新
            if current_time - self._last_progress_time >= 30:
                progress_msg = f"进度更新: 执行{stats.total_execs}次，路径{stats.paths_found}个，速度{stats.exec_speed:.1f}/秒"
                self._afl_state_history.append(progress_msg)
                self._last_progress_time = current_time
    
    def get_afl_status(self) -> dict[str, Any]:
        """获取AFL++当前状态"""
        if not self._afl_manager:
            return {'status': 'not_running', 'message': 'AFL++未启动'}
        
        status = self._afl_manager.get_status()
        
        # 生成动态进度消息（避免循环检测）
        with self._progress_lock:
            if self._afl_state_history:
                # 使用最近的状态历史生成摘要
                recent_states = self._afl_state_history[-3:]  # 最近3个状态
                status['recent_activity'] = ' | '.join(recent_states)
            else:
                status['recent_activity'] = 'AFL++运行中，暂无状态更新'
        
        return status
    
    def stop_afl_fuzzing(self, graceful: bool = True) -> bool:
        """停止AFL++模糊测试"""
        if not self._afl_manager:
            logger.warning("没有运行中的AFL++进程")
            return False
        
        try:
            success = self._afl_manager.stop_fuzzing(graceful=graceful)
            if success:
                logger.info("AFL++模糊测试已停止")
            return success
        except Exception as e:
            logger.error(f"停止AFL++模糊测试时出错: {e}")
            return False
        finally:
            self._afl_manager = None
    
    def get_afl_progress_message(self) -> str:
        """获取动态进度消息（专门用于避免循环检测）"""
        if not self._afl_manager:
            return "AFL++未运行"
        
        # 获取动态消息，包含时间戳确保唯一性
        return self._afl_manager.get_progress_message()
    
    def wait_for_afl_results(self, check_interval: int = 60, max_wait: int = 1800) -> dict[str, Any]:
        """智能等待AFL++结果（避免频繁轮询）
        
        Args:
            check_interval: 检查间隔（秒）
            max_wait: 最大等待时间（秒）
            
        Returns:
            dict: 等待结果和统计信息
        """
        if not self._afl_manager:
            return {'error': 'AFL++未运行'}
        
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            status = self._afl_manager.get_status()
            
            # 检查是否完成或出错
            if status['state'] in ['finished', 'error', 'terminated']:
                logger.info(f"AFL++运行结束，状态: {status['state']}")
                break
            
            # 检查是否发现崩溃
            crashes = self._afl_manager.get_crashes()
            if crashes:
                logger.info(f"AFL++发现 {len(crashes)} 个崩溃文件")
                return {
                    'success': True,
                    'crashes_found': len(crashes),
                    'crash_files': [str(f) for f in crashes],
                    'status': status
                }
            
            # 生成动态等待消息
            progress_msg = self.get_afl_progress_message()
            logger.info(f"AFL++等待中: {progress_msg}")
            
            # 等待指定间隔
            time.sleep(check_interval)
        
        # 超时或正常结束
        final_status = self._afl_manager.get_status() if self._afl_manager else {}
        crashes = self._afl_manager.get_crashes() if self._afl_manager else []
        
        return {
            'timeout': time.time() - start_time >= max_wait,
            'crashes_found': len(crashes),
            'crash_files': [str(f) for f in crashes],
            'status': final_status
        }
    
    def _get_security_context(self) -> str:
        """获取安全分析上下文信息
        
        Returns:
            str: 安全分析上下文描述
        """
        tools_status = self.get_security_tools_status()
        available_tools = [tool for tool, available in tools_status.items() if available]
        
        unavailable_tools = [tool for tool, available in tools_status.items() if not available]
        
        context = f"""
你是一个专业的安全分析助手，专门进行二进制安全分析和漏洞研究。

🔧 **当前可用工具**: {', '.join(available_tools) if available_tools else '基础工具'}
"""
        
        if unavailable_tools:
            context += f"""
⚠️  **不可用工具**: {', '.join(unavailable_tools)}
💡 **提示**: 要获得完整的安全分析功能，请确保运行环境使用openhands-security:latest镜像。
   你可以通过执行以下命令检查当前环境中的安全工具：
   `which afl-fuzz && which checksec && which klee || echo "部分工具不可用"`
"""
        
        # 添加AFL++状态信息
        if self._afl_manager:
            afl_status = self.get_afl_status()
            context += f"""

🚀 **AFL++模糊测试状态**: {afl_status.get('state', '未知')}
📊 **当前活动**: {afl_status.get('recent_activity', '无')}
💡 **建议**: 使用get_afl_status()和wait_for_afl_results()方法监控进度，避免频繁检查文件
"""
        
        context += """
🎯 **主要能力**:
1. **智能模糊测试**: 使用start_afl_fuzzing()启动，wait_for_afl_results()等待结果
2. **崩溃分析**: 使用GDB进行深度调试，分析崩溃原因和可利用性  
3. **符号执行**: 使用KLEE进行路径探索，发现深层逻辑漏洞
4. **静态分析**: 检查二进制安全特性，识别潜在风险点
5. **智能报告**: 生成专业的安全分析报告

📋 **推荐AFL++工作流程**:
1. 使用start_afl_fuzzing()启动智能模糊测试
2. 使用wait_for_afl_results()等待结果（避免频繁检查）
3. 使用get_afl_status()获取实时进度
4. 发现崩溃后使用GDB分析
5. 使用stop_afl_fuzzing()优雅终止

⚠️  **重要提示**:
- 避免使用ls检查crashes目录，使用get_afl_status()代替
- 避免使用killall终止进程，使用stop_afl_fuzzing()代替
- 使用wait_for_afl_results()进行智能等待，避免循环检测
"""
        return context
    
    def reset(self) -> None:
        """重置SecurityAgent状态"""
        super().reset()
        
        # 停止AFL++进程（如果正在运行）
        if self._afl_manager:
            try:
                self._afl_manager.stop_fuzzing(graceful=True)
            except Exception as e:
                logger.warning(f"重置时停止AFL++进程出错: {e}")
            finally:
                self._afl_manager = None
        
        # 清空状态历史
        with self._progress_lock:
            self._afl_state_history.clear()
            self._last_progress_time = 0
        
        logger.debug("SecurityAgent状态已重置")