"""Scoring and formatting helpers for printing results to the terminal."""

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


def print_report(results: list[Result]) -> None:
    print_table(
        ("case", "category", "expected", "noul", "band", "took", "correct"),
        [
            (
                r.name,
                r.category,
                LABELS[r.expected_secret],
                f"{r.noul:.3f}",
                r.band,
                f"{r.elapsed_ms:.0f} ms",
                "yes" if r.correct else "no",
            )
            for r in results
        ],
    )

    total = len(results)
    passed = sum(r.correct for r in results)
    review = sum(r.band == "review" for r in results)
    confident_wrong = sum(r.band not in ("review", LABELS[r.expected_secret]) for r in results)
    print(f"\n{passed}/{total} correct at threshold {THRESHOLD} ({passed / total:.0%}), AUC {auc(results):.3f}")
    print(
        f"{total - review - confident_wrong} confident and correct, "
        f"{review} in review band ({REVIEW_LOW}-{REVIEW_HIGH}), {confident_wrong} confident and wrong"
    )

    by_category: dict[tuple[bool, str], list[bool]] = defaultdict(list)
    for r in results:
        by_category[(r.expected_secret, r.category)].append(r.correct)
    print("\nper category (correct at threshold):")
    for (expected, category), outcomes in sorted(by_category.items(), key=lambda item: (not item[0][0], item[0][1])):
        print(f"  {LABELS[expected]:<9}  {category:<20} {sum(outcomes)}/{len(outcomes)}")
