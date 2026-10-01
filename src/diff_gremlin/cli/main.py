"""Entry point: parse intent, dispatch once, preserve useful exit status."""

import sys

from diff_gremlin.cli.parser import normalize_legacy, parser


def dispatch(args) -> tuple[str, int]:
    from diff_gremlin.cli import commands, doctor
    from diff_gremlin.reporting.serialization import json_text

    if args.command == "doctor":
        data = doctor.document()
        return (json_text(data) if args.format == "json" else doctor.render(data)), 0
    if args.command == "policy":
        from diff_gremlin.policy.thresholds import POLICY_VERSION, WEIGHTS

        return (
            f"Policy {POLICY_VERSION}\nWeights: {WEIGHTS}\nRequired gaps produce unknown. Critical findings, CC>50, duplication>60% and missing license block.\nFull policy: https://github.com/react-randy/diff-gremlin/blob/main/docs/score-policy.md\nExits: 0 complete; 1 gate failure; 2 operation/usage error; 3 incomplete.\n",
            0,
        )
    return (
        commands.check(args) if args.command == "check" else commands.comparison(args)
    )


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(
        normalize_legacy(list(sys.argv[1:] if arguments is None else arguments))
    )
    try:
        output, code = dispatch(args)
    except (OSError, ValueError, RuntimeError) as error:
        from diff_gremlin.process import redact
        from diff_gremlin.reporting.escaping import plain

        print(
            f"diff-gremlin: {args.command} failed: {plain(redact(str(error), {}))}",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print(
            "diff-gremlin: interrupted; disposable scan resources were cleaned up",
            file=sys.stderr,
        )
        return 130
    sys.stdout.write(output)
    return code
