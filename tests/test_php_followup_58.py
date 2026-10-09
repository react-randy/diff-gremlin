"""Native PHP uncertainty grouping and private-message admission controls."""

import json
from collections import Counter
from dataclasses import replace

import pytest
import test_polyglot

from diff_gremlin.analyzers.php.type_messages import diagnostic_message
from diff_gremlin.analyzers.php.type_output import (
    UNRESOLVED,
    diagnostics,
    display_findings,
    type_metrics,
)
from diff_gremlin.analyzers.php.types import analyze_php_types
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.process import run

context = test_polyglot.context


def test_native_local_member_errors_are_uncertain_with_raw_counts(context):
    observed = []

    def native(command, **kwargs):
        result = run(command, **kwargs)
        if "analyse" in command:
            data = json.loads("{" + result.stdout.partition("{")[2])
            observed.extend(
                message for row in data["files"].values() for message in row["messages"]
            )
            assert data["totals"]["file_errors"] == len(observed)
        return result

    ctx = context(
        [
            (
                "First.php",
                "php",
                '<?php class First { public function value(): int { return "wrong"; } public function call(): void { $this->missing(); echo $this->absent; self::unknown(); }}\nfunction useMissing(): void { undefinedLocal(); }\n',
            ),
            (
                "Second.php",
                "php",
                "<?php class Second { public function call(): void { $this->missing(); echo $this->absent; self::unknown(); }}\n",
            ),
            (
                "External.php",
                "php",
                "<?php #[AbsentAttribute] class External extends \\Absent\\ParentItem {}\n",
            ),
        ],
        native,
    )
    before = {file.path: file.path.read_bytes() for file in ctx.files}
    stage = analyze_php_types(ctx)
    counts = Counter(item["identifier"] for item in observed)
    assert stage.status == "limited", stage.reason
    assert "or local errors" in stage.reason
    assert stage_score(stage) is None
    assert stage.metrics["native_rule_counts"] == counts
    assert stage.metrics["native_diagnostic_count"] == len(observed) == 10
    assert stage.metrics["error_count"] == 1
    assert stage.metrics["warning_count"] == stage.metrics["unresolved_symbols"] == 9
    assert len(stage.findings) == 7
    for identifier in ("property.notFound", "method.notFound", "staticMethod.notFound"):
        finding = next(f for f in stage.findings if f.rule == "phpstan." + identifier)
        assert finding.value == 2 and finding.metric == "unresolved_reference_count"
        assert finding.path == "" and finding.line == 0 and finding.symbol == ""
        assert finding.confidence == "low" and "or local errors" in finding.message
        assert "First" in finding.message and "Second" in finding.message
        assert len(finding.message) <= 512
    local = next(f for f in stage.findings if f.rule == "phpstan.return.type")
    assert (local.path, local.line, local.severity) == ("First.php", 1, "medium")
    assert "First::value() should return int but returns string" in local.message
    assert "wrong" not in local.message
    single = next(f for f in stage.findings if f.rule == "phpstan.attribute.notFound")
    assert (single.path, single.line) == ("External.php", 1)
    assert before == {file.path: file.path.read_bytes() for file in ctx.files}
    assert not list(ctx.scratch.glob("phpstan-*"))


@pytest.mark.parametrize(
    "source,identifier,fragment",
    [
        (
            '<?php function localValue(): int { return "bad"; }\n',
            "return.type",
            "localValue() should return int but returns string",
        ),
        (
            '<?php function localTake(int $value): void {}\nlocalTake("bad");\n',
            "argument.type",
            "expects int, string given",
        ),
        (
            "<?php class Local implements MissingInterface {}\n",
            "interface.notFound",
            "unknown interface MissingInterface",
        ),
        (
            "<?php class Local { use MissingTrait; }\n",
            "trait.notFound",
            "unknown trait MissingTrait",
        ),
    ],
)
def test_native_type_and_remaining_reference_context(
    context, source, identifier, fragment
):
    stage = analyze_php_types(context([("local.php", "php", source)], run))
    assert stage.status == ("limited" if identifier in UNRESOLVED else "ok"), (
        stage.reason
    )
    finding = next(f for f in stage.findings if f.rule == "phpstan." + identifier)
    assert fragment in finding.message
    assert finding.path == "local.php" and finding.line > 0
    assert stage.metrics["native_rule_counts"][identifier] == 1
    assert stage.metrics["native_diagnostic_count"] == 1


@pytest.mark.parametrize(
    "message",
    [
        "Method Local::value() should return int but returns string('/private/secret').",
        "Method Local::value() should return int but returns 'literal-secret'.",
        "Method Local::value() should return int but returns C:\\private\\secret.",
        "Method Local::value() should return int but returns /private/secret.",
        "Method Local::value() should return int but returns abcdefghijklmnopqrstuvwxyz123456.",
        "Method Local::value() should return int but returns string. token=hidden",
        "Method Local::value() should return int but returns <script>secret</script>.",
        "Method Local::value() should return int but returns string.\x1b[31m",
        "Method Local::value() should return int but returns array{secret: 'value'}.",
        "Method Local::value() should return int but returns string.\nprivate-body",
        "x" * 4097,
    ],
)
def test_unsafe_message_is_not_admitted(message):
    assert diagnostic_message(message) == ""


def test_env_secret_cannot_be_retained_as_native_identifier(monkeypatch):
    monkeypatch.setenv("PRIVATE_API_TOKEN", "ShortSecret")
    assert diagnostic_message("Function ShortSecret not found.") == ""


_SHORT_CREDENTIALS = (
    "ghp_SyntheticToken",
    "gho_ShortToken",
    "ghu_ShortToken",
    "ghs_ShortToken",
    "ghr_ShortToken",
    "github_pat_ShortToken",
    "sk_ShortKey",
    "AKIAShortKey",
)


@pytest.mark.parametrize("name", (*_SHORT_CREDENTIALS, "sk-ShortKey"))
@pytest.mark.parametrize(
    "template",
    [
        "Function {name} not found.",
        "Call to an undefined method Local::{name}().",
        "Access to an undefined property Local::${name}.",
        "Method Local::value() should return int but returns {name}.",
    ],
)
def test_short_credential_prefix_never_enters_sanitized_context(name, template):
    assert len(name) < 24
    assert diagnostic_message(template.format(name=name)) == ""


def test_native_short_credential_names_stay_counted_without_public_context(context):
    observed = []

    def native(command, **kwargs):
        result = run(command, **kwargs)
        if "analyse" in command:
            data = json.loads("{" + result.stdout.partition("{")[2])
            observed.extend(
                message for row in data["files"].values() for message in row["messages"]
            )
        return result

    source = "<?php\n" + "\n".join(f"{name}();" for name in _SHORT_CREDENTIALS)
    stage = analyze_php_types(context([("synthetic.php", "php", source)], native))
    assert len(observed) == len(_SHORT_CREDENTIALS)
    assert all(item["identifier"] == "function.notFound" for item in observed)
    assert all(
        any(name in item["message"] for name in _SHORT_CREDENTIALS) for item in observed
    )
    assert stage.status == "limited" and stage_score(stage) is None
    assert stage.metrics["native_diagnostic_count"] == len(_SHORT_CREDENTIALS)
    assert stage.metrics["native_rule_counts"] == {
        "function.notFound": len(_SHORT_CREDENTIALS)
    }
    assert stage.metrics["error_count"] == 0
    assert stage.metrics["warning_count"] == len(_SHORT_CREDENTIALS)
    assert len(stage.findings) == 1
    assert stage.findings[0].value == len(_SHORT_CREDENTIALS)
    assert not any(
        name in finding.message
        for name in _SHORT_CREDENTIALS
        for finding in stage.findings
    )


def test_short_credential_prefix_filter_preserves_normal_native_context():
    message = "Function ask_Function not found."
    assert diagnostic_message(message) == message


def test_sanitized_evidence_is_plain_text(context):
    file = context([("owned.php", "php", "<?php echo 1;\n")]).files[0]
    rows = [
        _row(
            "return.type",
            message="Method Local_Name::value() should return int but returns string.",
        ),
        _row(
            "return.type",
            message="Method Local::value() should return int but returns string('private-literal').",
        ),
    ]
    findings, unresolved = diagnostics(
        json.dumps(_document(file, rows)), {file.path: file}, 1
    )
    assert unresolved == 0
    assert (
        "Local_Name::value() should return int but returns string."
        in findings[0].message
    )
    assert "\\_" not in findings[0].message
    assert "private-literal" not in findings[1].message
    assert findings[1].message == "PHPStan return.type diagnostic (snapshot level 5)"


def _document(file, messages):
    return {
        "totals": {"errors": 0, "file_errors": len(messages)},
        "errors": [],
        "files": {str(file.path): {"errors": len(messages), "messages": messages}},
    }


def _row(identifier="method.notFound", **values):
    return {
        "line": 1,
        "identifier": identifier,
        "message": "Call to an undefined method Local::missing().",
        "ignorable": True,
    } | values


@pytest.mark.parametrize("identifier", sorted(UNRESOLVED))
def test_each_explicit_family_reconciles_raw_and_grouped_rows(context, identifier):
    file = context([("owned.php", "php", "<?php echo 1;\n")]).files[0]
    rows = [_row(identifier), _row(identifier)]
    findings, unresolved = diagnostics(
        json.dumps(_document(file, rows)), {file.path: file}, 1
    )
    assert len(findings) == unresolved == 2
    shown = display_findings(findings)
    assert len(shown) == 1 and shown[0].value == 2
    assert type_metrics(findings, unresolved)["native_rule_counts"] == {identifier: 2}


@pytest.mark.parametrize(
    "name", ["ghp_Probe", "Box_sk_Probe", "GHP_Probe", "Box_AKIAProbe"]
)
def test_rejected_foreign_identity_withholds_credential_leaf(context, name):
    file = context([("owned.php", "php", "<?php echo 1;\n")]).files[0]
    data = _document(file, [_row()])
    data["files"] = {f"/foreign/{name}.php": data["files"][str(file.path)]}
    with pytest.raises(ValueError) as rejected:
        diagnostics(json.dumps(data), {file.path: file}, 1)
    reason = str(rejected.value)
    assert "foreign source" in reason and "unrecognized source identity" in reason
    assert name not in reason and "/foreign/" not in reason and "redacted" in reason


def test_native_rejected_identity_keeps_failed_status_without_credential_context(
    context,
):
    observed = []

    def corrupt_identity(command, **kwargs):
        result = run(command, **kwargs)
        if "analyse" not in command:
            return result
        prefix, separator, document = result.stdout.partition("{")
        data = json.loads(separator + document)
        assert data["totals"]["file_errors"] == 1
        observed.append(True)
        row = next(iter(data["files"].values()))
        data["files"] = {"/foreign/Box_ghp_Probe.php": row}
        return replace(result, stdout=prefix + json.dumps(data))

    source = '<?php function localValue(): int { return "wrong"; }\n'
    ctx = context([("owned.php", "php", source)], corrupt_identity)
    stage = analyze_php_types(ctx)
    assert observed and stage.status == "failed"
    assert not stage.findings and not stage.metrics and stage.analyzed_files == 0
    assert "unrecognized source identity" in stage.reason and "redacted" in stage.reason
    assert "ghp_Probe" not in stage.reason and "/foreign/" not in stage.reason
    assert ctx.files[0].path.read_text() == source


def test_unknown_notfound_family_is_not_hidden_as_uncertainty(context):
    file = context([("owned.php", "php", "<?php echo 1;\n")]).files[0]
    findings, unresolved = diagnostics(
        json.dumps(
            _document(file, [_row("invented.notFound"), _row("invented.notFound")])
        ),
        {file.path: file},
        1,
    )
    assert unresolved == 0 and len(display_findings(findings)) == 2
    assert all(f.severity == "medium" for f in findings)
    assert type_metrics(findings, unresolved)["native_rule_counts"] == {"other": 2}


@pytest.mark.parametrize(
    "corruption",
    [
        "foreign",
        "line",
        "bool-line",
        "schema",
        "file-count",
        "total-count",
        "bool-count",
        "exit",
        "invalid-exit",
        "bool-exit",
    ],
)
def test_groupable_rows_never_bypass_native_admission(context, corruption):
    file = context([("owned.php", "php", "<?php echo 1;\n")]).files[0]
    rows = [_row(), _row()]
    data = _document(file, rows)
    code = 1
    if corruption == "foreign":
        data["files"] = {"/foreign/escape.php": data["files"][str(file.path)]}
    elif corruption == "line":
        rows[1]["line"] = 300
    elif corruption == "bool-line":
        rows[1]["line"] = True
    elif corruption == "schema":
        rows[1]["ignorable"] = "true"
    elif corruption == "file-count":
        data["files"][str(file.path)]["errors"] = 1
    elif corruption == "total-count":
        data["totals"]["file_errors"] = 1
    elif corruption == "bool-count":
        data["totals"]["errors"] = False
    elif corruption == "invalid-exit":
        code = 2
    elif corruption == "bool-exit":
        code = True
    else:
        code = 0
    with pytest.raises((ValueError, TypeError)):
        diagnostics(json.dumps(data), {file.path: file}, code)
