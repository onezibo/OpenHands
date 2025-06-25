"""Security Agent Skills - 安全分析工具封装

提供AFL++、GDB、KLEE等专业安全工具的Python封装，
通过Agent Skills系统为SecurityAgent提供强大的安全分析能力。
"""

from .afl_skills import (
    start_fuzzing, 
    check_fuzzing_status, 
    collect_crashes,
    minimize_corpus,
    triage_crashes
)
from .gdb_skills import (
    analyze_crash, 
    batch_analyze_crashes,
    extract_crash_info,
    check_exploitability
)
from .klee_skills import (
    compile_for_klee,
    run_symbolic_execution,
    analyze_klee_results,
    generate_test_cases
)
from .analysis_skills import (
    check_binary_security,
    extract_functions,
    find_dangerous_functions,
    generate_security_report
)

__all__ = [
    # AFL++ skills
    'start_fuzzing', 'check_fuzzing_status', 'collect_crashes',
    'minimize_corpus', 'triage_crashes',
    # GDB skills 
    'analyze_crash', 'batch_analyze_crashes', 'extract_crash_info',
    'check_exploitability',
    # KLEE skills
    'compile_for_klee', 'run_symbolic_execution', 'analyze_klee_results',
    'generate_test_cases',
    # 通用分析skills
    'check_binary_security', 'extract_functions', 'find_dangerous_functions',
    'generate_security_report'
]