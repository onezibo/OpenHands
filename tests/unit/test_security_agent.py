"""SecurityAgent集成测试

测试SecurityAgent的基础功能和security skills的可用性。
"""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import pytest

from openhands.agenthub.security_agent.security_agent import SecurityAgent
from openhands.core.config import AgentConfig
from openhands.llm.llm import LLM


class TestSecurityAgent(unittest.TestCase):
    """SecurityAgent基础功能测试"""

    def setUp(self):
        """测试前准备"""
        self.mock_llm = Mock(spec=LLM)
        self.mock_llm.config = Mock()
        self.mock_llm.config.model = 'gpt-4'

        self.config = AgentConfig()
        self.agent = SecurityAgent(self.mock_llm, self.config)

    def test_security_agent_initialization(self):
        """测试SecurityAgent初始化"""
        self.assertIsInstance(self.agent, SecurityAgent)
        self.assertEqual(self.agent.VERSION, '1.0')
        self.assertIsNotNone(self.agent._security_tools_available)

    def test_security_tools_check(self):
        """测试安全工具可用性检查"""
        tools = self.agent._check_security_tools()

        # 验证返回的工具字典包含预期的工具
        expected_tools = ['afl++', 'gdb', 'klee', 'checksec', 'objdump']
        for tool in expected_tools:
            self.assertIn(tool, tools)
            self.assertIsInstance(tools[tool], bool)

    def test_security_context_generation(self):
        """测试安全分析上下文生成"""
        context = self.agent._get_security_context()

        self.assertIsInstance(context, str)
        self.assertIn('安全分析助手', context)
        self.assertIn('AFL++', context)
        self.assertIn('GDB', context)
        self.assertIn('KLEE', context)

    def test_prompt_manager_security_extension(self):
        """测试prompt管理器的安全扩展"""
        pm = self.agent.prompt_manager

        self.assertIsNotNone(pm)
        # 验证prompt目录是SecurityAgent特定的
        self.assertIn('security_agent', pm.prompt_dir)

    def test_sandbox_plugins_configuration(self):
        """测试沙箱插件配置"""
        plugins = self.agent.sandbox_plugins

        self.assertIsInstance(plugins, list)
        self.assertTrue(len(plugins) > 0)

        # 验证包含必要的插件
        [plugin.name for plugin in plugins]
        self.assertIn('AgentSkillsRequirement', str(plugins))


class TestSecuritySkills(unittest.TestCase):
    """Security Skills功能测试"""

    def setUp(self):
        """测试前准备"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, 'test_binary')
        self.test_input = os.path.join(self.test_dir, 'test_input')

        # 创建测试文件
        with open(self.test_binary, 'w') as f:
            f.write("#!/bin/bash\\necho 'test binary'\\n")
        os.chmod(self.test_binary, 0o755)

        with open(self.test_input, 'w') as f:
            f.write('test input data')

    def tearDown(self):
        """测试后清理"""
        import shutil

        shutil.rmtree(self.test_dir)

    @patch('subprocess.run')
    def test_check_binary_security_import(self, mock_run):
        """测试check_binary_security函数的导入和基础调用"""
        try:
            from openhands.runtime.plugins.agent_skills.security.analysis_skills import (
                check_binary_security,
            )

            # 模拟file命令输出
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = 'ELF 64-bit LSB executable'

            result = check_binary_security(self.test_binary)
            self.assertIsInstance(result, str)
            self.assertIn('二进制安全特性分析', result)

        except ImportError as e:
            self.skipTest(f'Security skills未正确安装: {e}')

    @patch('subprocess.run')
    def test_afl_skills_import(self, mock_run):
        """测试AFL++ skills的导入"""
        try:
            from openhands.runtime.plugins.agent_skills.security.afl_skills import (
                start_fuzzing,
            )

            # 模拟文件不存在的情况
            result = start_fuzzing(
                '/nonexistent/binary', '/nonexistent/input', '/tmp/output'
            )
            self.assertIn('错误', result)

        except ImportError as e:
            self.skipTest(f'AFL++ skills未正确安装: {e}')

    def test_gdb_skills_import(self):
        """测试GDB skills的导入"""
        try:
            from openhands.runtime.plugins.agent_skills.security.gdb_skills import (
                extract_crash_info,
            )

            # 测试extract_crash_info函数
            test_gdb_output = """
            Program received signal SIGSEGV, Segmentation fault.
            0x0000000000401234 in main () at test.c:10
            """

            crash_info = extract_crash_info(test_gdb_output)
            self.assertIsInstance(crash_info, dict)
            self.assertIn('signal', crash_info)
            self.assertEqual(crash_info['signal'], 'SIGSEGV')

        except ImportError as e:
            self.skipTest(f'GDB skills未正确安装: {e}')

    def test_klee_skills_import(self):
        """测试KLEE skills的导入"""
        try:
            from openhands.runtime.plugins.agent_skills.security.klee_skills import (
                compile_for_klee,
            )

            # 测试编译不存在的文件
            result = compile_for_klee('/nonexistent/source.c')
            self.assertIn('错误', result)

        except ImportError as e:
            self.skipTest(f'KLEE skills未正确安装: {e}')

    def test_analysis_skills_workspace_creation(self):
        """测试分析工作空间创建"""
        try:
            from openhands.runtime.plugins.agent_skills.security.analysis_skills import (
                create_analysis_workspace,
            )

            workspace_dir = os.path.join(self.test_dir, 'test_workspace')
            result = create_analysis_workspace(workspace_dir)

            self.assertIn('工作空间创建完成', result)
            self.assertTrue(os.path.exists(workspace_dir))
            self.assertTrue(
                os.path.exists(os.path.join(workspace_dir, 'fuzzing', 'input'))
            )
            self.assertTrue(os.path.exists(os.path.join(workspace_dir, 'crashes')))
            self.assertTrue(os.path.exists(os.path.join(workspace_dir, 'reports')))

        except ImportError as e:
            self.skipTest(f'Analysis skills未正确安装: {e}')


class TestSecurityAgentIntegration(unittest.TestCase):
    """SecurityAgent集成测试"""

    @patch('openhands.agenthub.security_agent.security_agent.Agent.register')
    def test_security_agent_registration(self, mock_register):
        """测试SecurityAgent注册"""
        # 重新导入模块以触发注册
        import importlib

        import openhands.agenthub.security_agent.security_agent

        importlib.reload(openhands.agenthub.security_agent.security_agent)

        # 验证注册调用
        mock_register.assert_called_with('SecurityAgent', SecurityAgent)

    def test_microagents_available(self):
        """测试安全分析微代理是否可用"""
        microagent_files = [
            'security_workflow.md',
            'afl_fuzzing.md',
            'crash_analysis.md',
        ]

        for microagent_file in microagent_files:
            microagent_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'microagents', microagent_file
            )
            self.assertTrue(
                os.path.exists(microagent_path), f'微代理文件不存在: {microagent_file}'
            )

    def test_docker_configuration_available(self):
        """测试Docker配置文件是否可用"""
        docker_files = [
            'Dockerfile.security-extension',
            'build-security-runtime.sh',
            'README.md',
        ]

        for docker_file in docker_files:
            docker_path = os.path.join(
                os.path.dirname(__file__),
                '..',
                '..',
                'containers',
                'security',
                docker_file,
            )
            self.assertTrue(
                os.path.exists(docker_path), f'Docker配置文件不存在: {docker_file}'
            )


# 性能测试（可选）
@pytest.mark.slow
class TestSecurityAgentPerformance(unittest.TestCase):
    """SecurityAgent性能测试"""

    def test_skills_import_time(self):
        """测试skills导入时间"""
        import time

        start_time = time.time()
        try:
            from openhands.runtime.plugins.agent_skills.security import *  # noqa: F403, F406

            import_time = time.time() - start_time

            # 导入时间应该在合理范围内（<5秒）
            self.assertLess(import_time, 5.0, 'Security skills导入时间过长')

        except ImportError as e:
            self.skipTest(f'Security skills未安装: {e}')

    def test_agent_initialization_time(self):
        """测试Agent初始化时间"""
        import time

        mock_llm = Mock(spec=LLM)
        mock_llm.config = Mock()
        mock_llm.config.model = 'gpt-4'
        config = AgentConfig()

        start_time = time.time()
        SecurityAgent(mock_llm, config)
        init_time = time.time() - start_time

        # 初始化时间应该在合理范围内（<2秒）
        self.assertLess(init_time, 2.0, 'SecurityAgent初始化时间过长')


if __name__ == '__main__':
    # 运行所有测试
    unittest.main(verbosity=2)
