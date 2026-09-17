"""Scoring and formatting helpers for printing results to the terminal."""

import statistics
from collections import defaultdict
from typing import NamedTuple

THRESHOLD = 0.5
# Nouls carry no separate confidence; values in this band are treated as "send to review".
REVIEW_LOW, REVIEW_HIGH = 0.3, 0.7

LABELS = {True: "secret", False: "no secret"}


class Result(NamedTuple):
    name: str
    category: str
    expected_secret: bool
    noul: float
    elapsed_ms: float
    server_ms: float | None
    retries: int

    @property
    def correct(self) -> bool:
        return (self.noul >= THRESHOLD) == self.expected_secret

    @property
    def band(self) -> str:
        if self.noul >= REVIEW_HIGH:
            return "secret"
        if self.noul >= REVIEW_LOW:
            return "review"
        return "no secret"


def auc(results: list[Result]) -> float:
    """Chance that a random positive gets a higher noul than a random negative (ties count half)."""
    positives = [r.noul for r in results if r.expected_secret]
    negatives = [r.noul for r in results if not r.expected_secret]
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def brier(results: list[Result]) -> float:
    """Mean squared gap between noul and label: 0 is perfect, 0.25 is always answering 0.5."""
    return statistics.fmean((r.noul - float(r.expected_secret)) ** 2 for r in results)


def latency(values: list[float]) -> str:
    # No p99: with 100 cases it sits between the two slowest requests, so max says the same.
    p95 = statistics.quantiles(values, n=20, method="inclusive")[-1] if len(values) > 1 else values[0]
    return (
        f"mean {statistics.fmean(values):.0f} ms, p50 {statistics.median(values):.0f} ms, "
        f"p95 {p95:.0f} ms, max {max(values):.0f} ms"
    )


def print_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    widths = [max(len(header), *(len(row[i]) for row in rows)) for i, header in enumerate(headers)]

    def line(char: str) -> str:
        return "+" + "+".join(char * (width + 2) for width in widths) + "+"

    def row(cells: tuple[str, ...]) -> str:
        return "| " + " | ".join(f"{cell:<{width}}" for cell, width in zip(cells, widths, strict=True)) + " |"

    print(line("-"))
    print(row(headers))
    print(line("="))
    for cells in rows:
        print(row(cells))
    print(line("-"))


def print_report(results: list[Result], wall_s: float, concurrency: int) -> None:
    print_table(
        ("case", "category", "expected", "noul", "band", "took", "server", "correct"),
        [
            (
                r.name,
                r.category,
                LABELS[r.expected_secret],
                f"{r.noul:.3f}",
                r.band,
                f"{r.elapsed_ms:.0f} ms",
                "-" if r.server_ms is None else f"{r.server_ms:.0f} ms",
                "yes" if r.correct else "no",
            )
            for r in results
        ],
    )

    total = len(results)
    passed = sum(r.correct for r in results)
    review = sum(r.band == "review" for r in results)
    confident_wrong = sum(r.band not in ("review", LABELS[r.expected_secret]) for r in results)
    secrets = [r for r in results if r.expected_secret]
    non_secrets = [r for r in results if not r.expected_secret]
    caught = sum(r.correct for r in secrets)
    flagged = caught + sum(not r.correct for r in non_secrets)
    print(f"\n{passed}/{total} correct at threshold {THRESHOLD} ({passed / total:.0%}), AUC {auc(results):.3f}")
    print(
        f"recall {caught}/{len(secrets)} secrets caught ({caught / len(secrets):.0%}), "
        f"precision {caught}/{flagged} flagged were secrets ({caught / flagged if flagged else 0:.0%})"
    )
    print(
        f"mean noul {statistics.fmean(r.noul for r in secrets):.3f} for secrets, "
        f"{statistics.fmean(r.noul for r in non_secrets):.3f} for non-secrets, "
        f"Brier score {brier(results):.3f} (0 is perfect, 0.25 is always 0.5)"
    )
    print(
        f"{total - review - confident_wrong} confident and correct, "
        f"{review} in review band ({REVIEW_LOW}-{REVIEW_HIGH}), {confident_wrong} confident and wrong"
    )

    by_category: dict[tuple[bool, str], list[Result]] = defaultdict(list)
    for r in results:
        by_category[(r.expected_secret, r.category)].append(r)
    print("\nper category (correct at threshold, mean noul):")
    for (expected, category), group in sorted(by_category.items(), key=lambda item: (not item[0][0], item[0][1])):
        correct = sum(r.correct for r in group)
        mean_noul = statistics.fmean(r.noul for r in group)
        print(f"  {LABELS[expected]:<9}  {category:<20} {f'{correct}/{len(group)}':>5}  {mean_noul:.3f}")

    server = [r.server_ms for r in results if r.server_ms is not None]
    retried = sum(r.retries > 0 for r in results)
    print(f"\nlatency ({total} requests, concurrency {concurrency}, {wall_s:.1f} s wall, {total / wall_s:.1f} req/s):")
    print(f"  round trip  {latency([r.elapsed_ms for r in results])}")
    if server:
        print(f"  server      {latency(server)}  (network time excluded)")
    if retried:
        print(f"  retried after 429/5xx: {retried} of {total} requests (their round trip includes the backoff)")
