"""Native Python AST and compiler-scope controls; fixture code never runs."""

import dis
from types import CodeType

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.domain.context import ScanContext, SourceFile


def _unexpected_process(*args, **kwargs):
    raise AssertionError("Python fixture analysis must not start a process")


def _assert_compiler_local_eval(source):
    pending = [compile(source, "sample.py", "exec")]
    loads = []
    while pending:
        code = pending.pop()
        pending.extend(value for value in code.co_consts if isinstance(value, CodeType))
        loads.extend(
            instruction.opname
            for instruction in dis.get_instructions(code)
            if instruction.argval == "eval"
            and instruction.opname.startswith("LOAD_")
            and instruction.opname != "LOAD_FAST_AND_CLEAR"
        )
    assert loads and set(loads) <= {"LOAD_FAST", "LOAD_FAST_CHECK"}


@pytest.fixture
def observe(tmp_path):
    def analyze(source):
        path = tmp_path / "sample.py"
        path.write_text(source, encoding="utf-8")
        file = SourceFile(path, path.name, "python", False, path.stat().st_size)
        context = ScanContext(
            tmp_path,
            (file,),
            (file,),
            ("python",),
            "full",
            10,
            tmp_path,
            _unexpected_process,
        )
        result = analyze_execution(context)
        assert result.status == "ok", result.reason
        assert result.analyzed_files == result.eligible_files == 1
        assert "private argument" not in repr(result)
        assert all(f.path == "sample.py" for f in result.findings)
        return result

    return analyze


@pytest.mark.parametrize(
    "source,locations",
    [
        ('work = lambda value=eval("private argument"): value\n', [(1, 21)]),
        ('work = lambda *, value=eval("private argument"): value\n', [(1, 24)]),
        ('work = lambda eval=eval("private argument"): eval("plain")\n', [(1, 20)]),
        (
            'work = lambda value=eval("private argument"), *, other: value\n',
            [(1, 21)],
        ),
        (
            'work = lambda value=eval("private argument"): eval("private argument")\n',
            [(1, 21), (1, 47)],
        ),
        (
            'class Owner(metaclass=eval("private argument")): pass\n',
            [(1, 23)],
        ),
        ('class Owner(**eval("private argument")): pass\n', [(1, 15)]),
        (
            'class Owner(metaclass=eval("private argument")):\n'
            '    eval = lambda value: value\n    eval("plain")\n',
            [(1, 23)],
        ),
        ('def work(value=eval("private argument")): return value\n', [(1, 16)]),
    ],
)
def test_eager_expressions_keep_enclosing_scope_and_locations(
    observe, source, locations
):
    result = observe(source)
    assert [(f.rule, f.severity, f.line, f.column) for f in result.findings] == [
        ("python.eval", "high", line, column) for line, column in locations
    ]
    assert (
        result.metrics["call_count"]
        == result.metrics["actionable_count"]
        == len(locations)
    )


@pytest.mark.parametrize(
    "expression",
    [
        'lambda value=eval("plain"): value',
        'lambda *, value=eval("plain"): value',
        'lambda eval=eval("plain"): eval("plain")',
        'lambda value: eval("plain")',
    ],
)
def test_lambda_defaults_and_body_respect_outer_callable_shadow(observe, expression):
    result = observe(f"def eval(value): return value\nwork = {expression}\n")
    assert not result.findings


@pytest.mark.parametrize("keyword", ['metaclass=eval("plain")', '**eval("plain")'])
def test_class_keywords_respect_enclosing_callable_shadow(observe, keyword):
    result = observe(f"def eval(value): return value\nclass Owner({keyword}): pass\n")
    assert not result.findings


def test_nested_lambda_defaults_use_outer_parameters(observe):
    result = observe('work = lambda eval: lambda value=eval("plain"): value\n')
    assert not result.findings


def test_lambda_defaults_preserve_import_alias_and_body_parameter_shadow(observe):
    result = observe(
        "from builtins import eval as inspect\n"
        'work = lambda inspect=inspect("private argument"): inspect("plain")\n'
    )
    assert [(f.rule, f.symbol, f.line, f.column) for f in result.findings] == [
        ("python.eval", "builtins.eval", 2, 23)
    ]


_DISPLAYS = [
    pytest.param("[", "]", "item", id="list"),
    pytest.param("{", "}", "item", id="set"),
    pytest.param("{", "}", "item: item", id="dict"),
    pytest.param("(", ")", "item", id="generator"),
]


@pytest.mark.parametrize("opening,closing,result", _DISPLAYS)
def test_later_iterable_uses_comprehension_target_shadow(
    observe, opening, closing, result
):
    source = (
        f"values = {opening}{result} for eval in callbacks "
        f'for item in [eval("plain")]{closing}\n'
    )
    _assert_compiler_local_eval(source)
    assert not observe(source).findings


@pytest.mark.parametrize("opening,closing,result", _DISPLAYS)
def test_leftmost_iterable_uses_enclosing_builtin_despite_local_target(
    observe, opening, closing, result
):
    source = (
        f'values = {opening}{result} for eval in eval("private argument") '
        f'for item in [eval("plain")]{closing}\n'
    )
    findings = observe(source).findings
    assert [(f.rule, f.severity, f.line) for f in findings] == [
        ("python.eval", "high", 1)
    ]
    assert findings[0].column == source.index('eval("private argument")') + 1


@pytest.mark.parametrize("opening,closing,result", _DISPLAYS)
def test_all_targets_are_lexical_locals_even_before_later_assignment(
    observe, opening, closing, result
):
    source = (
        f"values = {opening}{result} for first in callbacks "
        'if eval("plain") for item in [eval("plain")] '
        f"for eval in callbacks{closing}\n"
    )
    _assert_compiler_local_eval(source)
    assert not observe(source).findings


@pytest.mark.parametrize("opening,closing,result", _DISPLAYS)
def test_unshadowed_later_iterable_and_condition_keep_builtin_observations(
    observe, opening, closing, result
):
    source = (
        f"values = {opening}{result} for first in callbacks "
        'for item in eval("private argument") '
        f'if eval("private argument"){closing}\n'
    )
    findings = observe(source).findings
    assert [(f.rule, f.severity) for f in findings] == [("python.eval", "high")] * 2
    assert [f.column for f in findings] == [
        source.index('eval("private argument")') + 1,
        source.rindex('eval("private argument")') + 1,
    ]


@pytest.mark.parametrize("opening,closing,result", _DISPLAYS)
def test_destructured_targets_and_conditions_are_local_without_outer_leak(
    observe, opening, closing, result
):
    source = (
        f"values = {opening}{result} for (eval, *rest) in callbacks "
        'if eval("plain") for item in [eval("plain")]'
        f'{closing}\neval("private argument")\n'
    )
    assert [
        (f.rule, f.severity, f.line, f.column) for f in observe(source).findings
    ] == [("python.eval", "high", 2, 1)]


@pytest.mark.parametrize("opening,closing,result", _DISPLAYS)
def test_comprehension_result_respects_local_target(observe, opening, closing, result):
    result = result.replace("item", 'eval("plain")')
    source = f"values = {opening}{result} for eval in callbacks{closing}\n"
    assert not observe(source).findings


def test_class_scope_applies_to_leftmost_iterable_only(observe):
    source = (
        "class Owner:\n    eval = lambda value: value\n"
        '    values = [item for item in eval("plain") '
        'for other in eval("private argument")]\n'
    )
    findings = observe(source).findings
    assert [(f.rule, f.severity, f.line) for f in findings] == [
        ("python.eval", "high", 3)
    ]
    assert (
        findings[0].column
        == source.splitlines()[2].index('eval("private argument")') + 1
    )


def test_nested_comprehensions_keep_their_target_bindings_separate(observe):
    source = (
        "values = [[eval('plain') for eval in callbacks] "
        "for item in callbacks if eval('private argument')]\n"
    )
    findings = observe(source).findings
    assert [(f.rule, f.severity) for f in findings] == [("python.eval", "high")]
    assert findings[0].column == source.index("eval('private argument')") + 1
