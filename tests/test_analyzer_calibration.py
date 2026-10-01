"""Native controls for lexical sinks, language policy and complete Bedrock tokens."""

import base64
import hashlib
import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import urlencode

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.analyzers.javascript.lint import analyze_js_lint
from diff_gremlin.analyzers.secrets import analyze_secrets
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.process import trusted_path


def runner(command, *, cwd, timeout, **kwargs):
    result = subprocess.run(
        command,
        cwd=cwd,
        env={"PATH": trusted_path(cwd), "LANG": "C.UTF-8", "HOME": str(cwd)},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return RunResult(tuple(command), result.returncode, result.stdout, result.stderr)


@pytest.fixture
def context(tmp_path):
    root, scratch = tmp_path / "source", tmp_path / "scratch"
    root.mkdir()
    scratch.mkdir()

    def make(name, language, text):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        file = SourceFile(path, name, language, False, path.stat().st_size)
        return ScanContext(root, (file,), (file,), (language,), "full", 30, scratch, runner)

    return make


def require_tools(*names):
    if any(not shutil.which(name) for name in names):
        pytest.skip("Actual installed native tools required: " + ", ".join(names))


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            'import {exec} from "node:child_process";\n'
            'function unused() { const {spawn: exec} = require("node:child_process"); }\n'
            'exec("echo safe");',
            [(3, "javascript.shell-execution")],
        ),
        (
            'import {exec} from "node:child_process";\n'
            'function wrapper(exec) { exec("ordinary"); }',
            [],
        ),
        (
            'function first() { const {exec} = require("node:child_process"); }\n'
            'function second() { const exec = value => value; exec("ordinary"); }',
            [],
        ),
        (
            'import {exec} from "node:child_process";\n'
            '{ const exec = value => value; exec("ordinary"); }\n'
            'function nested() { exec("echo safe"); }\nexec("echo safe");',
            [(3, "javascript.shell-execution"), (4, "javascript.shell-execution")],
        ),
        (
            'import {exec} from "node:child_process";\n'
            'function wrapper() { exec("ordinary"); var exec = value => value; }',
            [],
        ),
        (
            'import {exec} from "node:child_process";\n'
            'try { throw 1; } catch (exec) { exec("ordinary"); }\nexec("echo safe");',
            [(3, "javascript.shell-execution")],
        ),
        (
            'import * as process from "node:child_process";\n'
            'function wrapper(process) { process.exec("ordinary"); }\n'
            'const launch = process.exec; launch("echo safe");',
            [(3, "javascript.shell-execution")],
        ),
        (
            'const process = require("child_process");\n'
            'const {exec: launch} = process; launch("echo safe");',
            [(2, "javascript.shell-execution")],
        ),
        (
            'import process = require("child_process");\nprocess.exec("echo safe");',
            [(2, "javascript.shell-execution")],
        ),
        (
            'import type {exec} from "child_process";\nexec("invalid type-only call");',
            [],
        ),
        (
            'const process = require("child_process");\n'
            'let launch; ({exec: launch} = process); launch("echo safe");',
            [(2, "javascript.shell-execution")],
        ),
        (
            'const {exec} = require("node:child_process");\n'
            'let launch; launch = exec; launch("echo safe");\n'
            'launch = value => value; launch("ordinary");',
            [(2, "javascript.shell-execution")],
        ),
        (
            'import {exec} from "node:child_process";\n'
            'function unused() { exec = value => value; }\nexec("echo safe");',
            [(3, "javascript.shell-execution")],
        ),
        (
            'function wrapper(require) { const {exec} = require("node:child_process"); '
            'exec("ordinary"); }',
            [],
        ),
        (
            'require("node:child_process").exec("echo safe");\n'
            'const process = require("node:child_process");\n'
            'process["spawn"]("echo", [], {shell: true});',
            [(1, "javascript.shell-execution"), (3, "javascript.shell-execution")],
        ),
        (
            "function wrapper(eval, Function, setTimeout, globalThis) {\n"
            'eval("ordinary"); new Function("ordinary"); setTimeout("ordinary"); '
            'globalThis.eval("ordinary"); }',
            [],
        ),
        (
            'const execute = eval; execute("1+1");\n'
            'function nested() { new Function("return 1"); }\n'
            'globalThis.setTimeout("alert(1)", 1);',
            [
                (1, "javascript.eval"),
                (2, "javascript.function-constructor"),
                (3, "javascript.string-timer"),
            ],
        ),
    ],
)
def test_js_lexical_owners(context, source, expected):
    require_tools("node", "tsc")
    result = analyze_execution(context("scope.ts", "typescript", source))
    assert result.status == "ok", result.reason
    assert [(f.line, f.rule) for f in result.findings] == expected


@pytest.mark.parametrize(
    "extension,source",
    [
        ("js", "const fs = require('node:fs');\nmodule.exports = fs;\n"),
        ("cjs", "const fs = require('node:fs');\nmodule.exports = fs;\n"),
        ("mjs", "import fs from 'node:fs';\nexport default fs;\n"),
    ],
)
def test_javascript_module_formats_preserve_correctness_policy(context, extension, source):
    require_tools("node", "eslint")
    result = analyze_js_lint(context("library." + extension, "javascript", source))
    assert result.status == "ok", result.reason
    assert not result.findings


def test_javascript_correctness_rules_remain_active(context):
    require_tools("node", "eslint")
    result = analyze_js_lint(context("bad.cjs", "javascript", "const value = 1; value = 2;\n"))
    assert result.status == "ok", result.reason
    assert "no-const-assign" in {f.rule for f in result.findings}


def test_typescript_policy_remains_scoped_to_typescript(context):
    require_tools("node", "eslint")
    result = analyze_js_lint(
        context("library.ts", "typescript", "const fs = require('node:fs'); export {fs};\n")
    )
    assert result.status == "ok", result.reason
    assert "@typescript-eslint/no-require-imports" in {f.rule for f in result.findings}


def encode_bedrock(payload):
    return "bedrock-api-key-" + base64.b64encode(payload.encode()).decode()


def bedrock_payload(region, session=False):
    # Nonfunctional synthetic SigV4 fields follow the AWS generator's URL shape.
    fields = {
        "Action": "CallWithBearerToken",
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": "AKIA"
        + "0123456789ABCDEF/20260101/"
        + region
        + "/bedrock/aws4_request",
        "X-Amz-Date": "20260101T000000Z",
        "X-Amz-Expires": "43200",
        "X-Amz-SignedHeaders": "host",
    }
    if session:
        fields["X-Amz-Security-Token"] = "synthetic/session+credential=" * 7
    fields["X-Amz-Signature"] = hashlib.sha256(b"nonfunctional calibration fixture").hexdigest()
    return "bedrock.amazonaws.com/?" + urlencode(fields) + "&Version=1"


@pytest.mark.parametrize(
    "region,session",
    [("us-east-1", False), ("eu-west-1", True), ("ap-southeast-2", False), ("cn-north-1", False)],
)
def test_full_synthetic_bedrock_credentials_are_detected_redacted(context, region, session):
    require_tools("gitleaks")
    token = encode_bedrock(bedrock_payload(region, session))
    result = analyze_secrets(context("credentials.txt", "text", token))
    assert result.status == "ok", result.reason
    assert result.tool == "gitleaks" and result.version == "8.30.1"
    assert "secret.aws-amazon-bedrock-api-key-short-lived" in {f.rule for f in result.findings}
    assert token not in repr(result)
    assert all(f.path == "credentials.txt" and f.line == 1 for f in result.findings)
    # Independent regex capture check: the detector captures the credential, not a hostname.
    asset = Path(__file__).parents[1] / "src/diff_gremlin/analyzers/assets/gitleaks-v8.30.1.toml"
    rule = next(
        row
        for row in tomllib.loads(asset.read_text())["rules"]
        if row["id"] == "aws-amazon-bedrock-api-key-short-lived"
    )
    match = re.search(rule["regex"], token)
    assert match and match.group(rule["secretGroup"]) == token


@pytest.mark.parametrize("control", ["marker", "truncated", "unsigned", "ordinary"])
def test_bedrock_public_incomplete_ordinary_controls_are_not_credentials(context, control):
    require_tools("gitleaks")
    payload = bedrock_payload("us-east-1")
    samples = {
        "marker": encode_bedrock("bedrock.amazonaws.com"),
        "truncated": encode_bedrock(payload)[:-48],
        "unsigned": encode_bedrock(payload.split("&X-Amz-Signature=")[0] + "&Version=1"),
        "ordinary": encode_bedrock("bedrock.amazonaws.com/ordinary documentation&Version=1"),
    }
    result = analyze_secrets(context("documentation.txt", "text", samples[control]))
    assert result.status == "ok", result.reason
    assert not result.findings


def test_gitleaks_all_upstream_rule_identifiers_are_retained():
    asset = Path(__file__).parents[1] / "src/diff_gremlin/analyzers/assets/gitleaks-v8.30.1.toml"
    rules = tomllib.loads(asset.read_text())["rules"]
    assert len(rules) == 222
    assert len({rule["id"] for rule in rules}) == 222
    # Sorted IDs fingerprint the complete pinned upstream rule inventory.
    identifiers = "\n".join(sorted(rule["id"] for rule in rules))
    assert hashlib.sha256(identifiers.encode()).hexdigest() == (
        "71c98377587b028db1b5e5e73cd6b786b429d64dca971e5cc652046cb984bd69"
    )
    assert "paths" not in tomllib.loads(asset.read_text())["allowlist"]
