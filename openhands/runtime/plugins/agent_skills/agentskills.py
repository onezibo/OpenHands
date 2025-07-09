from inspect import signature

from openhands.runtime.plugins.agent_skills import file_ops, file_reader
from openhands.runtime.plugins.agent_skills.utils.dependency import import_functions

import_functions(
    module=file_ops, function_names=file_ops.__all__, target_globals=globals()
)
import_functions(
    module=file_reader, function_names=file_reader.__all__, target_globals=globals()
)

__all__ = file_ops.__all__ + file_reader.__all__

try:
    from openhands.runtime.plugins.agent_skills import repo_ops

    import_functions(
        module=repo_ops, function_names=repo_ops.__all__, target_globals=globals()
    )

    __all__ += repo_ops.__all__
except ImportError:
    # If repo_ops is not available, we just skip importing it.
    pass

try:
    from openhands.runtime.plugins.agent_skills import security

    import_functions(
        module=security, function_names=security.__all__, target_globals=globals()
    )

    __all__ += security.__all__
except ImportError:
    # If security skills are not available (e.g., missing AFL++, GDB, etc.),
    # we just skip importing them to avoid breaking other functionality.
    pass


DOCUMENTATION = ''
for func_name in __all__:
    func = globals()[func_name]

    cur_doc = func.__doc__
    # remove indentation from docstring and extra empty lines
    cur_doc = '\n'.join(filter(None, map(lambda x: x.strip(), cur_doc.split('\n'))))
    # now add a consistent 4 indentation
    cur_doc = '\n'.join(map(lambda x: ' ' * 4 + x, cur_doc.split('\n')))

    fn_signature = f'{func.__name__}' + str(signature(func))
    DOCUMENTATION += f'{fn_signature}:\n{cur_doc}\n\n'


# Add file_editor (a function)
from openhands.runtime.plugins.agent_skills.file_editor import file_editor  # noqa: E402

__all__ += ['file_editor']
