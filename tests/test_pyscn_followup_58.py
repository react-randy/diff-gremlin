"""Native null-zero clone results and strict contradictory-envelope controls."""

import json
from dataclasses import replace

import pytest
import test_polyglot

from diff_gremlin.analyzers.python.pyscn import analyze_pyscn
from diff_gremlin.process import run

context = test_polyglot.context

_SOURCES = [
    (
        "alpha.py",
        "def fold_window(values, width):\n    total = 0\n    left = 0\n    result = []\n    for right, value in enumerate(values):\n        total += value\n        if right - left >= width:\n            total -= values[left]\n            left += 1\n        if right - left + 1 == width:\n            result.append(total / width)\n    return result\n",
    ),
    (
        "beta.py",
        "def parse_sections(lines):\n    sections = {}\n    current = None\n    for raw in lines:\n        text = raw.strip()\n        if text.startswith('#') or not text:\n            continue\n        if text.startswith('[') and text.endswith(']'):\n            current = text[1:-1]\n            sections.setdefault(current, {})\n            continue\n        key, separator, value = text.partition('=')\n        if separator and current is not None:\n            sections[current][key.strip()] = value.strip()\n    return sections\n",
    ),
    (
        "gamma.py",
        "def decode_runs(tokens):\n    iterator = iter(tokens)\n    chunks = []\n    while True:\n        try:\n            count = next(iterator)\n        except StopIteration:\n            break\n        item = next(iterator, None)\n        if item is None:\n            raise ValueError('Incomplete run')\n        if not isinstance(count, int) or count < 0:\n            raise ValueError('Invalid count')\n        chunks.extend([item] * count)\n    return tuple(chunks)\n",
    ),
    (
        "delta.py",
        "def paths_from_edges(edges, start, stop):\n    graph = {}\n    for source, destination in edges:\n        graph.setdefault(source, set()).add(destination)\n    stack = [(start, [start])]\n    completed = []\n    while stack:\n        node, path = stack.pop()\n        if node == stop:\n            completed.append(path)\n        else:\n            for neighbor in sorted(graph.get(node, ())):\n                if neighbor not in path:\n                    stack.append((neighbor, path + [neighbor]))\n    return completed\n",
    ),
]


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "missing-groups",
        "nonzero-groups",
        "bool-groups",
        "nonzero-percent",
        "nonzero-pairs-count",
        "missing-pairs",
        "nonempty-pairs",
        "invalid-pairs",
        "missing-clone-count",
        "bool-clone-count",
        "nonzero-clone-count",
        "nonzero-fragments",
        "false-success",
        "coverage",
        "nested-null",
    ],
)
def test_native_zero_clone_null_envelope_and_contradictions(context, mutation):
    observed = []

    def capture(command, **kwargs):
        result = run(command, **kwargs)
        if (
            "analyze" not in command
            or "clones" not in command[command.index("--select") + 1]
        ):
            return result
        data = json.loads(result.stdout)
        clone, summary = data["clone"], data["summary"]
        stats = clone["statistics"]
        assert clone["clone_groups"] is None and clone["clone_pairs"] is None
        assert summary["clone_groups"] == stats["total_clone_groups"] == 0
        observed.append(True)
        if mutation == "missing-groups":
            clone.pop("clone_groups")
        elif mutation == "nonzero-groups":
            summary["clone_groups"] = stats["total_clone_groups"] = 1
        elif mutation == "bool-groups":
            summary["clone_groups"] = stats["total_clone_groups"] = False
        elif mutation == "nonzero-percent":
            summary["code_duplication_percentage"] = 1
        elif mutation == "nonzero-pairs-count":
            stats["total_clone_pairs"] = 1
        elif mutation == "missing-pairs":
            clone.pop("clone_pairs")
        elif mutation == "nonempty-pairs":
            clone["clone_pairs"] = [{}]
        elif mutation == "invalid-pairs":
            clone["clone_pairs"] = {}
        elif mutation == "missing-clone-count":
            stats.pop("total_clones")
        elif mutation == "bool-clone-count":
            stats["total_clones"] = False
        elif mutation == "nonzero-clone-count":
            stats["total_clones"] = 1
        elif mutation == "nonzero-fragments":
            stats["duplicated_fragments"] = 1
        elif mutation == "false-success":
            clone["success"] = False
        elif mutation == "coverage":
            stats["files_analyzed"] = 0
        elif mutation == "nested-null":
            summary["clone_groups"] = stats["total_clone_groups"] = 1
            clone["clone_groups"] = [{"id": 1, "clones": None}]
        return replace(result, stdout=json.dumps(data))

    ctx = context(
        [
            (
                name,
                "python",
                text + "".join(f"# unique padding {name} {i}\n" for i in range(35)),
            )
            for name, text in _SOURCES
        ],
        capture,
    )
    before = {file.path: file.path.read_bytes() for file in ctx.files}
    stage = analyze_pyscn(ctx)[1]
    assert observed
    assert stage.status == ("failed" if mutation else "ok"), stage.reason
    if mutation:
        assert not stage.findings and not stage.metrics and stage.analyzed_files == 0
    else:
        assert stage.metrics == {"duplication_percent": 0.0, "clone_groups": 0}
        assert stage.analyzed_files == stage.eligible_files == 4
    assert before == {file.path: file.path.read_bytes() for file in ctx.files}
