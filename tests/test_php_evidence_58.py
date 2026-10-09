"""Native PHPStan contextual identities and hostile identity controls."""

import json

import pytest
import test_polyglot

from diff_gremlin.analyzers.php.type_output import diagnostics
from diff_gremlin.analyzers.php.types import analyze_php_types
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.process import run

context = test_polyglot.context

_TRAIT = '<?php namespace App; trait Value { public function value(): int { return "wrong"; } }\n'
_MODEL = "<?php namespace App; class Model { use Value; }\n"


def test_native_trait_context_reproduces_foreign_key_without_trusting_foreign_files(
    context,
):
    native_keys = []

    def observed(command, **kwargs):
        result = run(command, **kwargs)
        if "analyse" in command:
            data = json.loads("{" + result.stdout.partition("{")[2])
            native_keys.extend(data["files"])
        return result

    ctx = context(
        [("Value.php", "php", _TRAIT), ("Model.php", "php", _MODEL)], observed
    )
    before = {file.path: file.path.read_bytes() for file in ctx.files}
    stage = analyze_php_types(ctx)
    assert any(key.endswith(" (in context of class App\\Model)") for key in native_keys)
    assert stage.status == "ok", stage.reason
    assert [
        (finding.rule, finding.path, finding.line) for finding in stage.findings
    ] == [("phpstan.return.type", "Value.php", 1)]
    assert before == {file.path: file.path.read_bytes() for file in ctx.files}
    assert not list(ctx.scratch.glob("phpstan-*"))


def test_native_laravel_like_trait_preserves_unresolved_framework_limit(context):
    ctx = context(
        [
            ("Value.php", "php", _TRAIT),
            (
                "Model.php",
                "php",
                "<?php namespace App; class Model extends \\Illuminate\\Database\\Eloquent\\Model { use Value; }\n",
            ),
        ],
        run,
    )
    stage = analyze_php_types(ctx)
    assert stage.status == "limited", stage.reason
    assert any(finding.rule == "phpstan.return.type" for finding in stage.findings)
    assert any(finding.rule == "phpstan.class.notFound" for finding in stage.findings)
    assert stage.analyzed_files == 2 and stage_score(stage) is None


@pytest.mark.parametrize(
    "identity",
    [
        "/foreign/escape.php",
        "/foreign/escape.php (in context of class App\\Model)",
        "{owned} (in context of class ../escape.php)",
        "{owned} (in context of class App\\Model) trailing",
        "{owned} (in context of trait App\\Model)",
        "/private/secret/evil\x1b[31m`file`.php",
    ],
)
def test_php_foreign_and_unproven_contexts_remain_rejected_with_safe_identity(
    context, identity
):
    ctx = context([("owned.php", "php", "<?php echo 1;\n")])
    file = ctx.files[0]
    data = {
        "totals": {"errors": 0, "file_errors": 1},
        "errors": [],
        "files": {
            identity.format(owned=file.path): {
                "errors": 1,
                "messages": [
                    {
                        "line": 1,
                        "identifier": "return.type",
                        "message": "hidden",
                        "ignorable": True,
                    }
                ],
            },
        },
    }
    with pytest.raises(ValueError, match="foreign source") as error:
        diagnostics(json.dumps(data), {file.path: file}, 1)
    reason = str(error.value)
    assert "/private" not in reason and "/foreign" not in reason
    assert "\x1b" not in reason and "`" not in reason
    assert len(reason) < 250
