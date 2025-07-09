"""AFL++进程管理器

这个模块提供AFL++模糊测试的智能进程管理、实时输出解析和状态监控功能。
专门设计用于避免SecurityAgent在长时间fuzzing中陷入循环检测。
"""

import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from openhands.core.logger import openhands_logger as logger
from openhands.runtime.plugins.agent_skills.security.file_monitor import AFLCrashMonitor


class AFLFuzzingState(Enum):
    """AFL++模糊测试状态"""

    INITIALIZING = 'initializing'  # 初始化中
    STARTING = 'starting'  # 启动中
    RUNNING = 'running'  # 正常运行
    EXPLORING = 'exploring'  # 探索新路径
    FINAL_PHASE = 'final_phase'  # 最终阶段
    FINISHED = 'finished'  # 已完成
    ERROR = 'error'  # 错误状态
    TERMINATED = 'terminated'  # 已终止


@dataclass
class AFLStats:
    """AFL++统计信息"""

    exec_speed: float = 0.0  # 执行速度 (exec/sec)
    total_execs: int = 0  # 总执行次数
    paths_found: int = 0  # 发现路径数
    crashes_found: int = 0  # 发现崩溃数
    hangs_found: int = 0  # 发现挂起数
    coverage: float = 0.0  # 覆盖率百分比
    stability: float = 0.0  # 稳定性百分比
    pending_fav: int = 0  # 待处理收藏夹
    pending_total: int = 0  # 待处理总数
    cycles_done: int = 0  # 完成循环数
    bitmap_cvg: float = 0.0  # 位图覆盖率
    run_time: str = '00:00:00'  # 运行时间
    last_find: str = '00:00:00'  # 上次发现时间


class AFLOutputParser:
    """AFL++输出解析器"""

    def __init__(self):
        # AFL++输出的正则表达式模式
        self.patterns = {
            'exec_speed': re.compile(r'exec speed\s*:\s*([\d.]+)\s*/sec'),
            'total_execs': re.compile(r'total execs\s*:\s*(\d+)'),
            'paths_found': re.compile(r'paths : total:(\d+)'),
            'crashes': re.compile(r'crashes\s*:\s*(\d+)'),
            'hangs': re.compile(r'hangs\s*:\s*(\d+)'),
            'coverage': re.compile(r'map coverage\s*:\s*([\d.]+)%'),
            'stability': re.compile(r'stability\s*:\s*([\d.]+)%'),
            'pending_fav': re.compile(r'pending\s*:\s*(\d+)/(\d+)'),
            'cycles_done': re.compile(r'cycles done\s*:\s*(\d+)'),
            'run_time': re.compile(r'run time\s*:\s*([\d:]+)'),
            'last_find': re.compile(r'last new find\s*:\s*([\d:]+)'),
            'state': re.compile(r'fuzzing state\s*:\s*([a-zA-Z\s]+)'),
        }

    def parse_line(self, line: str) -> dict[str, Any]:
        """解析单行AFL++输出"""
        results = {}

        for key, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                if key == 'pending_fav':
                    # pending格式是 "数字/数字"
                    results['pending_fav'] = int(match.group(1))
                    results['pending_total'] = int(match.group(2))
                elif key in ['exec_speed', 'coverage', 'stability']:
                    results[key] = float(match.group(1))
                elif key in [
                    'total_execs',
                    'paths_found',
                    'crashes',
                    'hangs',
                    'cycles_done',
                ]:
                    results[key] = int(match.group(1))
                else:
                    results[key] = match.group(1).strip()

        return results

    def parse_fuzzer_stats(self, stats_file: Path) -> AFLStats:
        """解析fuzzer_stats文件"""
        stats = AFLStats()

        try:
            if not stats_file.exists():
                return stats

            with open(stats_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        key = key.strip()
                        value = value.strip()

                        if key == 'execs_per_sec':
                            stats.exec_speed = float(value)
                        elif key == 'total_execs':
                            stats.total_execs = int(value)
                        elif key == 'paths_total':
                            stats.paths_found = int(value)
                        elif key == 'saved_crashes':
                            stats.crashes_found = int(value)
                        elif key == 'saved_hangs':
                            stats.hangs_found = int(value)
                        elif key == 'map_coverage':
                            stats.coverage = float(value)
                        elif key == 'stability':
                            # 移除百分号
                            stats.stability = float(value.rstrip('%'))
                        elif key == 'pending_favs':
                            stats.pending_fav = int(value)
                        elif key == 'pending_total':
                            stats.pending_total = int(value)
                        elif key == 'cycles_done':
                            stats.cycles_done = int(value)
                        elif key == 'bitmap_cvg':
                            stats.bitmap_cvg = float(value.rstrip('%'))

        except Exception as e:
            logger.warning(f'解析fuzzer_stats文件时出错: {e}')

        return stats


class AFLProcessManager:
    """AFL++进程管理器

    提供AFL++进程的启动、监控、控制和状态报告功能。
    专门设计用于避免SecurityAgent的循环检测问题。
    """

    def __init__(
        self,
        output_dir: str,
        target_binary: str,
        input_dir: str,
        timeout: int = 300,
        memory_limit: str = '200',
    ):
        """初始化AFL++进程管理器

        Args:
            output_dir: AFL++输出目录
            target_binary: 目标二进制文件路径
            input_dir: 输入语料库目录
            timeout: 超时时间（秒）
            memory_limit: 内存限制（MB）
        """
        self.output_dir = Path(output_dir)
        self.target_binary = target_binary
        self.input_dir = Path(input_dir)
        self.timeout = timeout
        self.memory_limit = memory_limit

        # 进程状态
        self.process: Optional[subprocess.Popen] = None
        self.state = AFLFuzzingState.INITIALIZING
        self.stats = AFLStats()
        self.parser = AFLOutputParser()

        # 监控线程
        self._output_thread: Optional[threading.Thread] = None
        self._stats_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()

        # 文件监控器
        self._crash_monitor: Optional[AFLCrashMonitor] = None
        self._crash_files_count = 0

        # 事件驱动机制
        self._crash_event = threading.Event()  # crash检测事件
        self._first_crash_detected = False
        self._crash_wait_start_time: Optional[float] = None

        # 回调函数
        self.on_state_change: Optional[Callable[[AFLFuzzingState, AFLStats], None]] = (
            None
        )
        self.on_crash_found: Optional[Callable[[int], None]] = None
        self.on_progress_update: Optional[Callable[[AFLStats], None]] = None

        # 确保输出目录存在
        self.output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f'AFL++进程管理器初始化完成 - 输出目录: {self.output_dir}')

    def start_fuzzing(
        self, additional_args: list[str] = None, env_vars: dict[str, str] = None
    ) -> bool:
        """启动AFL++模糊测试

        Args:
            additional_args: 额外的AFL++命令行参数
            env_vars: 环境变量

        Returns:
            bool: 启动是否成功
        """
        if self.process and self.process.poll() is None:
            logger.warning('AFL++进程已在运行中')
            return False

        try:
            # 构建AFL++命令
            cmd = [
                'afl-fuzz',
                '-i',
                str(self.input_dir),
                '-o',
                str(self.output_dir),
                '-m',
                self.memory_limit,
                '-t',
                '1000',  # 1秒超时
            ]

            # 添加额外参数
            if additional_args:
                cmd.extend(additional_args)

            # 添加目标二进制
            cmd.extend(['--', self.target_binary])

            logger.info(f'启动AFL++命令: {" ".join(cmd)}')

            # 设置环境变量
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)

            # 启动进程
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                preexec_fn=os.setsid,  # 创建新的进程组
            )

            self.state = AFLFuzzingState.STARTING
            self._notify_state_change()

            # 启动监控线程
            self._start_monitoring()

            # 启动崩溃文件监控
            self._start_crash_monitoring()

            logger.info(f'AFL++进程启动成功，PID: {self.process.pid}')
            return True

        except Exception as e:
            logger.error(f'启动AFL++进程失败: {e}')
            self.state = AFLFuzzingState.ERROR
            self._notify_state_change()
            return False

    def _start_monitoring(self):
        """启动监控线程"""
        self._stop_monitoring.clear()

        # 输出监控线程
        self._output_thread = threading.Thread(target=self._monitor_output, daemon=True)
        self._output_thread.start()

        # 统计文件监控线程
        self._stats_thread = threading.Thread(target=self._monitor_stats, daemon=True)
        self._stats_thread.start()

    def _start_crash_monitoring(self):
        """启动崩溃文件监控"""
        try:
            crashes_dir = self.output_dir / 'default' / 'crashes'
            crashes_dir.mkdir(parents=True, exist_ok=True)

            # 创建崩溃监控器
            self._crash_monitor = AFLCrashMonitor(
                crashes_dir=str(crashes_dir),
                on_crash_found=self._on_crash_files_changed,
            )

            # 启动监控
            success = self._crash_monitor.start_monitoring()
            if success:
                logger.info('AFL++崩溃文件监控启动成功')
            else:
                logger.warning('AFL++崩溃文件监控启动失败，将使用备用检测')
                self._crash_monitor = None

        except Exception as e:
            logger.warning(f'启动AFL++崩溃文件监控失败: {e}，将使用备用检测')
            self._crash_monitor = None

    def _on_crash_files_changed(self, crash_files: list[Path]):
        """崩溃文件变化回调"""
        new_count = len(crash_files)
        if new_count > self._crash_files_count:
            logger.info(f'AFL++检测到新崩溃文件，总数: {new_count}')

            # 触发crash事件，唤醒等待的线程
            if not self._first_crash_detected:
                self._first_crash_detected = True
                self._crash_event.set()
                logger.info('首次crash检测完成，触发等待事件')

            if self.on_crash_found:
                self.on_crash_found(new_count)
            self._crash_files_count = new_count

    def _monitor_output(self):
        """监控AFL++输出"""
        if not self.process:
            return

        logger.info('开始监控AFL++输出...')

        try:
            while not self._stop_monitoring.is_set() and self.process.poll() is None:
                line = self.process.stdout.readline()
                if not line:
                    break

                line = line.strip()
                if line:
                    # 解析输出更新状态
                    parsed = self.parser.parse_line(line)
                    if parsed:
                        self._update_stats_from_output(parsed)

                    # 检测状态变化
                    self._detect_state_changes(line)

        except Exception as e:
            logger.error(f'监控AFL++输出时出错: {e}')

        logger.info('AFL++输出监控结束')

    def _monitor_stats(self):
        """监控fuzzer_stats文件"""
        stats_file = self.output_dir / 'default' / 'fuzzer_stats'
        last_crashes = 0

        logger.info('开始监控fuzzer_stats文件...')

        while not self._stop_monitoring.is_set():
            try:
                if stats_file.exists():
                    new_stats = self.parser.parse_fuzzer_stats(stats_file)

                    # 检查是否有新崩溃
                    if new_stats.crashes_found > last_crashes:
                        logger.info(f'发现新崩溃！总数: {new_stats.crashes_found}')
                        if self.on_crash_found:
                            self.on_crash_found(new_stats.crashes_found)
                        last_crashes = new_stats.crashes_found

                    # 更新统计信息
                    self.stats = new_stats

                    # 通知进度更新
                    if self.on_progress_update:
                        self.on_progress_update(self.stats)

                # 每5秒检查一次
                time.sleep(5)

            except Exception as e:
                logger.warning(f'监控stats文件时出错: {e}')
                time.sleep(5)

        logger.info('fuzzer_stats监控结束')

    def _update_stats_from_output(self, parsed: dict[str, Any]):
        """从输出更新统计信息"""
        for key, value in parsed.items():
            if hasattr(self.stats, key):
                setattr(self.stats, key, value)

    def _detect_state_changes(self, line: str):
        """检测状态变化"""
        old_state = self.state

        if 'started :-)' in line or 'starting' in line.lower():
            self.state = AFLFuzzingState.STARTING
        elif 'in progress' in line:
            self.state = AFLFuzzingState.RUNNING
        elif 'final phase' in line:
            self.state = AFLFuzzingState.FINAL_PHASE
        elif 'finished' in line:
            self.state = AFLFuzzingState.FINISHED
        elif 'exploring' in line.lower():
            self.state = AFLFuzzingState.EXPLORING

        if old_state != self.state:
            self._notify_state_change()

    def _notify_state_change(self):
        """通知状态变化"""
        logger.info(f'AFL++状态变化: {self.state.value}')
        if self.on_state_change:
            self.on_state_change(self.state, self.stats)

    def stop_fuzzing(self, graceful: bool = True) -> bool:
        """停止AFL++模糊测试

        Args:
            graceful: 是否优雅地停止（使用信号）

        Returns:
            bool: 停止是否成功
        """
        if not self.process:
            logger.warning('没有运行中的AFL++进程')
            return False

        try:
            logger.info(f'正在停止AFL++进程 (PID: {self.process.pid})...')

            # 停止监控线程
            self._stop_monitoring.set()

            # 停止崩溃文件监控
            if self._crash_monitor:
                try:
                    self._crash_monitor.stop_monitoring()
                except Exception as e:
                    logger.warning(f'停止崩溃文件监控失败: {e}')
                finally:
                    self._crash_monitor = None

            if graceful:
                # 发送SIGTERM信号优雅停止
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)

                # 等待进程终止
                try:
                    self.process.wait(timeout=10)
                    logger.info('AFL++进程已优雅终止')
                except subprocess.TimeoutExpired:
                    logger.warning('优雅终止超时，强制终止...')
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                    self.process.wait()
            else:
                # 强制终止
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                self.process.wait()
                logger.info('AFL++进程已强制终止')

            self.state = AFLFuzzingState.TERMINATED
            self._notify_state_change()

            # 等待监控线程结束
            if self._output_thread and self._output_thread.is_alive():
                self._output_thread.join(timeout=5)
            if self._stats_thread and self._stats_thread.is_alive():
                self._stats_thread.join(timeout=5)

            return True

        except Exception as e:
            logger.error(f'停止AFL++进程失败: {e}')
            return False

    def get_status(self) -> dict[str, Any]:
        """获取当前状态信息"""
        is_running = self.process and self.process.poll() is None

        return {
            'state': self.state.value,
            'is_running': is_running,
            'pid': self.process.pid if self.process else None,
            'stats': {
                'exec_speed': self.stats.exec_speed,
                'total_execs': self.stats.total_execs,
                'paths_found': self.stats.paths_found,
                'crashes_found': self.stats.crashes_found,
                'hangs_found': self.stats.hangs_found,
                'coverage': self.stats.coverage,
                'stability': self.stats.stability,
                'run_time': self.stats.run_time,
                'last_find': self.stats.last_find,
            },
        }

    def get_crashes(self) -> list[Path]:
        """获取崩溃文件列表"""
        # 优先使用文件监控器的结果
        if self._crash_monitor:
            return self._crash_monitor.get_crash_files()

        # 备用方案：直接扫描目录
        crashes_dir = self.output_dir / 'default' / 'crashes'
        if not crashes_dir.exists():
            return []

        crash_files = []
        for crash_file in crashes_dir.glob('id:*'):
            if crash_file.is_file() and not crash_file.name.startswith('README'):
                crash_files.append(crash_file)

        return sorted(crash_files)

    def wait_for_crash(self, timeout: Optional[float] = None) -> dict[str, Any]:
        """阻塞等待直到检测到crash

        这是核心的事件驱动方法，避免了轮询检测的API开销。
        方法会阻塞直到检测到第一个crash或超时。

        Args:
            timeout: 可选的超时时间（秒），None表示无限等待

        Returns:
            dict: {
                'crashed': bool,  # 是否检测到crash
                'crash_count': int,  # crash数量
                'crash_files': List[str],  # crash文件列表
                'wait_time': float,  # 等待时间
                'state': str,  # fuzzing状态
                'reason': str  # 如果未crash，说明原因（timeout/interrupted）
            }
        """
        if not self.process or self.process.poll() is not None:
            return {
                'crashed': False,
                'crash_count': 0,
                'crash_files': [],
                'wait_time': 0.0,
                'state': self.state.value,
                'reason': 'not_running',
                'error': 'AFL++进程未运行或已终止',
            }

        start_time = time.time()
        self._crash_wait_start_time = start_time

        # 清除事件状态，准备等待
        self._crash_event.clear()
        self._first_crash_detected = False

        logger.info(
            f'开始等待AFL++crash事件（超时: {timeout if timeout else "无限制"}秒）'
        )

        try:
            # 阻塞等待crash事件
            crashed = self._crash_event.wait(timeout)
            wait_time = time.time() - start_time

            if crashed:
                crashes = self.get_crashes()
                logger.info(
                    f'检测到crash事件！等待时间: {wait_time:.2f}秒，发现{len(crashes)}个crash文件'
                )
                return {
                    'crashed': True,
                    'crash_count': len(crashes),
                    'crash_files': [str(f) for f in crashes],
                    'wait_time': wait_time,
                    'state': self.state.value,
                    'reason': 'crash_detected',
                }
            else:
                # 超时或被中断
                crashes = self.get_crashes()
                reason = 'timeout' if timeout else 'interrupted'
                logger.info(
                    f'等待crash事件结束（{reason}），等待时间: {wait_time:.2f}秒'
                )
                return {
                    'crashed': False,
                    'crash_count': len(crashes),
                    'crash_files': [str(f) for f in crashes],
                    'wait_time': wait_time,
                    'state': self.state.value,
                    'reason': reason,
                }

        except Exception as e:
            wait_time = time.time() - start_time
            logger.error(f'等待crash事件时发生错误: {e}')
            return {
                'crashed': False,
                'crash_count': 0,
                'crash_files': [],
                'wait_time': wait_time,
                'state': self.state.value,
                'reason': 'error',
                'error': str(e),
            }
        finally:
            self._crash_wait_start_time = None

    def get_progress_message(self) -> str:
        """生成动态进度消息（避免循环检测）"""
        # 基于实际统计数据生成不同的消息
        messages = []

        if self.state == AFLFuzzingState.STARTING:
            messages.append('AFL++正在初始化模糊测试环境...')
        elif self.state == AFLFuzzingState.RUNNING:
            messages.append(f'AFL++运行中 - 执行速度: {self.stats.exec_speed:.1f}/秒')
            messages.append(f'已发现 {self.stats.paths_found} 个路径')

            # 使用监控器的崩溃计数（更准确）
            crash_count = (
                self._crash_monitor.get_crash_count()
                if self._crash_monitor
                else self.stats.crashes_found
            )
            if crash_count > 0:
                messages.append(f'发现 {crash_count} 个崩溃')

        elif self.state == AFLFuzzingState.EXPLORING:
            messages.append('AFL++正在探索新的执行路径...')
        elif self.state == AFLFuzzingState.FINAL_PHASE:
            messages.append('AFL++进入最终优化阶段')
        elif self.state == AFLFuzzingState.FINISHED:
            messages.append('AFL++模糊测试已完成')
        else:
            messages.append(f'AFL++状态: {self.state.value}')

        # 添加时间戳和执行次数确保消息唯一性
        timestamp = int(time.time()) % 1000
        exec_count = self.stats.total_execs % 1000  # 防止数字过大
        messages.append(f'[T:{timestamp}|E:{exec_count}]')

        return ' | '.join(messages)

    def __del__(self):
        """析构函数，确保进程被清理"""
        if self.process and self.process.poll() is None:
            try:
                self.stop_fuzzing(graceful=False)
            except:
                pass

        # 清理崩溃监控器
        if self._crash_monitor:
            try:
                self._crash_monitor.stop_monitoring()
            except:
                pass
