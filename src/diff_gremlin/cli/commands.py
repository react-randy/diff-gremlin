"""Own source lifetimes for each requested scan operation."""

from diff_gremlin.cli.output import render
from diff_gremlin.orchestration.scan import scan
from diff_gremlin.policy.gates import Gates, exit_code
from diff_gremlin.reporting.delta import compare_document


def gates_for(args) -> Gates:
    return Gates(args.fail_under, args.fail_on, args.require_complete)


def check(args) -> tuple[str, int]:
    from diff_gremlin.acquisition.snapshots import acquire_source

    with acquire_source(args.target, ref=args.ref, timeout=args.timeout) as snapshot:
        report = scan(snapshot, profile=args.profile, timeout=args.timeout)
        return render(report, args.format), exit_code(
            report.assessment, report.stages, gates_for(args)
        )


def comparison(args) -> tuple[str, int]:
    from diff_gremlin.acquisition.snapshots import acquire_comparison
    from diff_gremlin.providers.resolve import resolve_review

    review = resolve_review(args.url, timeout=args.timeout) if args.command == "pr" else None
    target = review.base_repo_url if review else args.target
    base = review.base_sha if review else args.base
    head = review.head_sha if review else args.head
    with acquire_comparison(target, base, head, review=review, timeout=args.timeout) as pair:
        before = scan(pair.base, profile=args.profile, timeout=args.timeout)
        after = scan(pair.head, profile=args.profile, timeout=args.timeout)
        document = compare_document(
            before, after, review=review, comparison_base_sha=pair.comparison_base_sha
        )
        code = exit_code(after.assessment, after.stages, gates_for(args))
        if not before.assessment.complete and code == 0:
            code = 3
        return render(after, args.format, document), code
