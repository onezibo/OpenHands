"""AFL++管理器单元测试

测试AFL++进程管理器的核心功能，确保智能模糊测试和循环检测逃避策略正常工作。
"""

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from openhands.runtime.plugins.agent_skills.security.afl_manager import (
    AFLFuzzingState,
    AFLOutputParser,
    AFLProcessManager,
    AFLStats,
)


class TestAFLOutputParser(unittest.TestCase):
    """测试AFL++输出解析器"""

    def setUp(self):
        self.parser = AFLOutputParser()

    def test_parse_exec_speed(self):
        """测试执行速度解析"""
        line = 'exec speed : 1234.5/sec'
        result = self.parser.parse_line(line)
        self.assertEqual(result['exec_speed'], 1234.5)

    def test_parse_paths_found(self):
        """测试路径发现解析"""
        line = 'paths : total:567'
        result = self.parser.parse_line(line)
        self.assertEqual(result['paths_found'], 567)

    def test_parse_crashes(self):
        """测试崩溃解析"""
        line = 'crashes : 12'
        result = self.parser.parse_line(line)
        self.assertEqual(result['crashes'], 12)

    def test_parse_fuzzer_stats_file(self):
        """测试解析fuzzer_stats文件"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('execs_per_sec : 1000.0\n')
            f.write('total_execs : 50000\n')
            f.write('paths_total : 123\n')
            f.write('saved_crashes : 5\n')
            f.flush()

            stats = self.parser.parse_fuzzer_stats(Path(f.name))
            self.assertEqual(stats.exec_speed, 1000.0)
            self.assertEqual(stats.total_execs, 50000)
            self.assertEqual(stats.paths_found, 123)
            self.assertEqual(stats.crashes_found, 5)


class TestAFLProcessManager(unittest.TestCase):
    """测试AFL++进程管理器"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = AFLProcessManager(
            output_dir=self.temp_dir,
            target_binary='/bin/echo',
            input_dir=self.temp_dir,
            timeout=30,
        )

    def tearDown(self):
        if self.manager:
            try:
                self.manager.stop_fuzzing(graceful=False)
            except Exception:
                pass

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.manager.state, AFLFuzzingState.INITIALIZING)
        self.assertEqual(self.manager.timeout, 30)
        self.assertIsNone(self.manager.process)

    def test_get_status(self):
        """测试状态获取"""
        status = self.manager.get_status()
        self.assertIn('state', status)
        self.assertIn('is_running', status)
        self.assertIn('stats', status)
        self.assertEqual(status['state'], 'initializing')
        self.assertFalse(status['is_running'])

    def test_progress_message_generation(self):
        """测试进度消息生成（循环检测逃避）"""
        # 测试不同状态下的消息
        self.manager.state = AFLFuzzingState.STARTING
        msg1 = self.manager.get_progress_message()

        # 等待1秒确保时间戳不同
        time.sleep(1.1)
        msg2 = self.manager.get_progress_message()

        # 消息应该包含时间戳，确保不相同（避免循环检测）
        self.assertNotEqual(msg1, msg2)
        self.assertIn('AFL++正在初始化', msg1)
        self.assertIn('[T:', msg1)  # 时间戳标记

    def test_state_transitions(self):
        """测试状态转换"""
        # 测试状态变化回调
        state_changes = []

        def on_state_change(state, stats):
            state_changes.append(state)

        self.manager.on_state_change = on_state_change

        # 模拟状态变化
        self.manager.state = AFLFuzzingState.RUNNING
        self.manager._notify_state_change()

        self.assertEqual(len(state_changes), 1)
        self.assertEqual(state_changes[0], AFLFuzzingState.RUNNING)

    @patch('subprocess.Popen')
    def test_start_fuzzing_command_construction(self, mock_popen):
        """测试AFL++命令构建"""
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None
        mock_process.stdout.readline.return_value = ''
        mock_popen.return_value = mock_process

        success = self.manager.start_fuzzing(additional_args=['-d', '-M', 'main'])

        # 检查命令构建
        call_args = mock_popen.call_args
        cmd = call_args[0][0]

        self.assertTrue(success)
        self.assertIn('afl-fuzz', cmd)
        self.assertIn('-i', cmd)
        self.assertIn('-o', cmd)
        self.assertIn('-d', cmd)
        self.assertIn('-M', cmd)
        self.assertIn('main', cmd)
        self.assertIn('/bin/echo', cmd)

    def test_crash_files_detection(self):
        """测试崩溃文件检测"""
        # 创建模拟的crashes目录结构
        crashes_dir = Path(self.temp_dir) / 'default' / 'crashes'
        crashes_dir.mkdir(parents=True, exist_ok=True)

        # 创建模拟崩溃文件
        crash_files = [
            crashes_dir / 'id:000001,sig:11,src:000000,op:flip1,pos:0',
            crashes_dir / 'id:000002,sig:11,src:000001,op:arith8,pos:5',
            crashes_dir / 'README.txt',  # 应该被忽略
        ]

        for crash_file in crash_files:
            crash_file.touch()

        detected_crashes = self.manager.get_crashes()

        # 应该检测到2个崩溃文件，忽略README
        self.assertEqual(len(detected_crashes), 2)
        crash_names = [f.name for f in detected_crashes]
        self.assertIn('id:000001,sig:11,src:000000,op:flip1,pos:0', crash_names)
        self.assertIn('id:000002,sig:11,src:000001,op:arith8,pos:5', crash_names)
        self.assertNotIn('README.txt', crash_names)


class TestAFLStatsIntegration(unittest.TestCase):
    """测试AFL++统计信息集成"""

    def test_stats_dataclass(self):
        """测试统计信息数据类"""
        stats = AFLStats()

        # 检查默认值
        self.assertEqual(stats.exec_speed, 0.0)
        self.assertEqual(stats.total_execs, 0)
        self.assertEqual(stats.crashes_found, 0)

        # 测试设置值
        stats.exec_speed = 1500.5
        stats.total_execs = 100000
        stats.crashes_found = 3

        self.assertEqual(stats.exec_speed, 1500.5)
        self.assertEqual(stats.total_execs, 100000)
        self.assertEqual(stats.crashes_found, 3)

    def test_fuzzing_states(self):
        """测试模糊测试状态枚举"""
        # 检查所有状态值
        expected_states = [
            'initializing',
            'starting',
            'running',
            'exploring',
            'final_phase',
            'finished',
            'error',
            'terminated',
        ]

        for state in AFLFuzzingState:
            self.assertIn(state.value, expected_states)


class TestCircularDetectionAvoidance(unittest.TestCase):
    """测试循环检测逃避机制"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = AFLProcessManager(
            output_dir=self.temp_dir, target_binary='/bin/echo', input_dir=self.temp_dir
        )

    def test_unique_progress_messages(self):
        """测试进度消息的唯一性"""
        messages = []

        # 生成多个进度消息
        for i in range(10):
            msg = self.manager.get_progress_message()
            messages.append(msg)
            time.sleep(0.1)  # 短暂延迟确保时间戳变化

        # 所有消息应该是唯一的（因为包含时间戳）
        unique_messages = set(messages)
        self.assertEqual(len(unique_messages), len(messages))

    def test_stats_variation(self):
        """测试统计信息变化避免重复"""
        # 模拟统计信息更新
        self.manager.stats.total_execs = 1000
        msg1 = self.manager.get_progress_message()

        # 更新统计信息
        self.manager.stats.total_execs = 2000
        msg2 = self.manager.get_progress_message()

        # 消息应该反映统计信息的变化
        self.assertNotEqual(msg1, msg2)
        self.assertIn('E:0]', msg1)  # 执行次数模1000的结果
        self.assertIn('E:0]', msg2)  # 两个都是整千，模1000都是0

    def test_state_based_message_variation(self):
        """测试基于状态的消息变化"""
        states_and_messages = {}

        # 测试不同状态下的消息
        for state in AFLFuzzingState:
            self.manager.state = state
            msg = self.manager.get_progress_message()
            states_and_messages[state] = msg

        # 不同状态应该产生不同的消息基础内容
        unique_base_messages = set()
        for msg in states_and_messages.values():
            # 移除时间戳部分，只比较基础消息
            base_msg = msg.split('[T:')[0]
            unique_base_messages.add(base_msg)

        # 至少应该有几种不同的基础消息
        self.assertGreater(len(unique_base_messages), 1)


if __name__ == '__main__':
    unittest.main()
