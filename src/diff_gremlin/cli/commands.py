"""Own source lifetimes for each requested scan operation."""

from diff_gremlin.cli.output import render
from diff_gremlin.cli.progress import stage_progress
from diff_gremlin.orchestration.scan import scan
from diff_gremlin.policy.gates import Gates, exit_code
from diff_gremlin.reporting.delta import compare_document


def gates_for(args) -> Gates:
    return Gates(args.fail_under, args.fail_on, args.require_complete)


def check(args) -> tuple[str, int]:
    from diff_gremlin.acquisition.snapshots import acquire_source

    with acquire_source(args.target, ref=args.ref, timeout=args.timeout) as snapshot:
        report = scan(
            snapshot,
            profile=args.profile,
            timeout=args.timeout,
            progress=stage_progress(quiet=args.quiet),
        )
        return render(report, args.format), exit_code(
            report.assessment, report.stages, gates_for(args)
        )


def comparison(args) -> tuple[str, int]:
    from diff_gremlin.acquisition.snapshots import acquire_comparison
    from diff_gremlin.policy.comparison import comparison_exit_code
    from diff_gremlin.providers.resolve import resolve_review

    review = (
        resolve_review(args.url, timeout=args.timeout) if args.command == "pr" else None
    )
    target = review.base_repo_url if review else args.target
    base = review.base_sha if review else args.base
    head = review.head_sha if review else args.head
    with acquire_comparison(
        target,
        base,
        head,
        review=review,
        timeout=args.timeout,
        paths=tuple(args.paths),
        changed_paths=args.changed_paths,
    ) as pair:
        before = scan(
            pair.base,
            profile=args.profile,
            timeout=args.timeout,
            progress=stage_progress(quiet=args.quiet, side="base"),
        )
        after = scan(
            pair.head,
            profile=args.profile,
            timeout=args.timeout,
            progress=stage_progress(quiet=args.quiet, side="head"),
        )
        document = compare_document(
            before,
            after,
            review=review,
            comparison_base_sha=pair.comparison_base_sha,
            base_changed_lines=pair.base_changed_lines,
            head_changed_lines=pair.head_changed_lines,
        )
        code = comparison_exit_code(before, after, document, gates_for(args))
        return render(after, args.format, document), code
