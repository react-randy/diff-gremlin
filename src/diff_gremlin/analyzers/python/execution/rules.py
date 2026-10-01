"""Classify selected Python call syntax without inspecting argument text."""

import ast

_PYTHON_DYNAMIC = {
    "eval": "python.eval",
    "builtins.eval": "python.eval",
    "exec": "python.exec",
    "builtins.exec": "python.exec",
}
_PYTHON_PROCESS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}


def _process_rule(node: ast.Call, name: str):
    shell = next((keyword.value for keyword in node.keywords if keyword.arg == "shell"), None)
    if name.endswith(("getoutput", "getstatusoutput")):
        return "python.shell-execution", "high"
    if shell is not None and not (isinstance(shell, ast.Constant) and shell.value is False):
        return "python.shell-execution", "high"
    return "python.process-call", "info"


def _python_rule(node: ast.Call, name: str):
    if name in _PYTHON_DYNAMIC:
        return _PYTHON_DYNAMIC[name], "high"
    if name in {"compile", "builtins.compile"}:
        return "python.dynamic-compile", "info"
    if name in {"os.system", "os.popen"}:
        return "python.shell-execution", "high"
    return _process_rule(node, name) if name in _PYTHON_PROCESS else None
