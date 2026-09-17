"""Small formatting helpers for printing results to the terminal."""


def print_table(rows: list[tuple[str, float, str, float, bool]]) -> None:
    headers = ("case", "noul", "verdict", "took", "correct")
    name_width = max(len(headers[0]), *(len(name) for name, _, _, _, _ in rows))
    verdict_width = max(len(headers[2]), *(len(verdict) for _, _, verdict, _, _ in rows))
    took_width = max(len(headers[3]), *(len(f"{elapsed_ms:.0f} ms") for _, _, _, elapsed_ms, _ in rows))
    correct_width = len(headers[4])

    def line(char: str) -> str:
        return (
            "+"
            + char * (name_width + 2)
            + "+"
            + char * 8
            + "+"
            + char * (verdict_width + 2)
            + "+"
            + char * (took_width + 2)
            + "+"
            + char * (correct_width + 2)
            + "+"
        )

    def row(name: str, noul: str, verdict: str, took: str, correct: str) -> str:
        return (
            f"| {name:<{name_width}} | {noul:<6} | {verdict:<{verdict_width}} "
            f"| {took:<{took_width}} | {correct:<{correct_width}} |"
        )

    print(line("-"))
    print(row(*headers))
    print(line("="))
    for name, noul, verdict, elapsed_ms, correct in rows:
        print(row(name, f"{noul:.3f}", verdict, f"{elapsed_ms:.0f} ms", "yes" if correct else "no"))
    print(line("-"))

    total = len(rows)
    passed = sum(1 for *_, correct in rows if correct)
    print(f"\n{passed}/{total} correct ({passed / total:.0%})")
