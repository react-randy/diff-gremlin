"""Dispatch structurally parsed review URLs to immutable provider adapters."""

import math

from diff_gremlin.domain.sources import ReviewTarget
from diff_gremlin.providers.github import resolve_github
from diff_gremlin.providers.gitlab import resolve_gitlab
from diff_gremlin.providers.urls import parse_review_url


def resolve_review(url: str, *, timeout: float = 30.0) -> ReviewTarget:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Provider timeout must be a positive finite number")
    review = parse_review_url(url)
    resolver = resolve_github if review.provider == "github" else resolve_gitlab
    return resolver(review, timeout=timeout)
