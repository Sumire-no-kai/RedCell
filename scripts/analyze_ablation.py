"""Aggregate the preregistered Phase 0 ablation matrix from SQLite.

Expected matrix: static/random/thompson × budgets 20/100 × seeds 5000/5001/5002.
Only complete runs matching every expected cell are accepted. Queries to first Finding
remain censored when a run has no Finding; the report never substitutes its budget.
"""

from __future__ import annotations

import argparse
import html
import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median

from redcell.protocols.finding import Finding
from redcell.protocols.run import Run, RunStatus
from redcell.protocols.trace import Attempt
from redcell.storage import DEFAULT_URL, RunStore

ALGORITHMS = ("static", "random", "thompson")
BUDGETS = (20, 100)
DEFAULT_SEEDS = (5000, 5001, 5002)


@dataclass(frozen=True)
class RunResult:
    run_id: str
    algorithm: str
    budget: int
    seed: int
    queries_to_first_finding: int | None
    finding_count: int


@dataclass(frozen=True)
class GroupSummary:
    algorithm: str
    budget: int
    runs: int
    first_finding_observed: int
    first_finding_censored: int
    first_finding_median: float | None
    first_finding_iqr: list[float] | None
    finding_count_median: float
    finding_count_iqr: list[float]


def queries_to_first_finding(
    attempts: Sequence[Attempt], findings: Sequence[Finding]
) -> int | None:
    """Return the first attempt containing any Level-1 Finding.

    This deliberately differs from Attempt ASR: the ablation's preregistered primary
    metric is any Finding, not a new threshold over shaped reward or triad fields.
    """

    finding_attempt_ids = {finding.attempt_id for finding in findings}
    return next(
        (
            index
            for index, attempt in enumerate(attempts, start=1)
            if attempt.id in finding_attempt_ids
        ),
        None,
    )


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile of no values")
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return float(ordered[lower])
    fraction = index - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def _median_iqr(values: Sequence[float]) -> tuple[float, list[float]]:
    return float(median(values)), [_percentile(values, 0.25), _percentile(values, 0.75)]


def _expected_keys(seeds: Iterable[int]) -> set[tuple[str, int, int]]:
    return {
        (algorithm, budget, seed)
        for algorithm in ALGORITHMS
        for budget in BUDGETS
        for seed in seeds
    }


def load_results(store: RunStore, seeds: Sequence[int]) -> list[RunResult]:
    expected = _expected_keys(seeds)
    matching: dict[tuple[str, int, int], Run] = {}

    for run in store.list_runs():
        if run.seed is None or run.limits.max_attempts is None:
            continue
        key = (run.algorithm, run.limits.max_attempts, run.seed)
        if key not in expected:
            continue
        if key in matching:
            raise ValueError(f"重复的消融单元 {key}: {matching[key].id} 与 {run.id}")
        matching[key] = run

    missing = sorted(expected - matching.keys())
    if missing:
        raise ValueError(f"缺少预注册的消融 run: {missing}")

    incomplete = [run.id for run in matching.values() if run.status is not RunStatus.COMPLETED]
    if incomplete:
        raise ValueError(f"消融只接受 COMPLETED run,以下 run 不可用于结论:{incomplete}")
    _require_comparable_conditions(list(matching.values()))

    results: list[RunResult] = []
    for key, run in sorted(matching.items()):
        attempts = store.attempts_for(run.id)
        findings = store.findings_for(run.id)
        results.append(
            RunResult(
                run_id=run.id,
                algorithm=key[0],
                budget=key[1],
                seed=key[2],
                queries_to_first_finding=queries_to_first_finding(attempts, findings),
                finding_count=len(findings),
            )
        )
    return results


def _require_comparable_conditions(runs: Sequence[Run]) -> None:
    """拒绝混杂 treatment；旧 Run 没有完整快照也不能悄悄混进正式实验。"""
    missing = [run.id for run in runs if not run.has_auditable_conditions]
    if missing:
        raise ValueError(f"消融 run 缺少可审计实验条件:{missing}")
    fingerprints = {run.experiment_fingerprint for run in runs}
    if len(fingerprints) != 1:
        by_run = {run.id: run.experiment_fingerprint for run in runs}
        raise ValueError(f"消融 run 的实验条件指纹不一致:{by_run}")


def summarise(results: Sequence[RunResult]) -> list[GroupSummary]:
    summaries: list[GroupSummary] = []
    for budget in BUDGETS:
        for algorithm in ALGORITHMS:
            group = [
                result
                for result in results
                if result.budget == budget and result.algorithm == algorithm
            ]
            first_values = [
                float(result.queries_to_first_finding)
                for result in group
                if result.queries_to_first_finding is not None
            ]
            finding_counts = [float(result.finding_count) for result in group]
            first_median, first_iqr = _median_iqr(first_values) if first_values else (None, None)
            count_median, count_iqr = _median_iqr(finding_counts)
            summaries.append(
                GroupSummary(
                    algorithm=algorithm,
                    budget=budget,
                    runs=len(group),
                    first_finding_observed=len(first_values),
                    first_finding_censored=len(group) - len(first_values),
                    first_finding_median=first_median,
                    first_finding_iqr=first_iqr,
                    finding_count_median=count_median,
                    finding_count_iqr=count_iqr,
                )
            )
    return summaries


def _format_iqr(values: list[float] | None) -> str:
    return "—" if values is None else f"[{values[0]:.2f}, {values[1]:.2f}]"


def render_html(summaries: Sequence[GroupSummary]) -> str:
    max_findings = max((summary.finding_count_median for summary in summaries), default=0.0)
    rows = []
    for summary in summaries:
        width = 0.0 if max_findings == 0 else 100 * summary.finding_count_median / max_findings
        first_median = (
            "—" if summary.first_finding_median is None else f"{summary.first_finding_median:.2f}"
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(summary.algorithm)}</td>"
            f"<td>{summary.budget}</td>"
            f"<td>{summary.first_finding_observed}/{summary.runs} observed "
            f"({summary.first_finding_censored} censored)</td>"
            f"<td>{first_median} / {_format_iqr(summary.first_finding_iqr)}</td>"
            f"<td>{summary.finding_count_median:.2f} / {_format_iqr(summary.finding_count_iqr)}"
            f'<div class="bar" style="width:{width:.1f}%"></div></td>'
            "</tr>"
        )
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><title>RedCell Phase 0 ablation</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #172033; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccd5e1; padding: .55rem; text-align: left; vertical-align: top; }}
th {{ background: #edf3fb; }}
.bar {{ min-width: 2px; height: .55rem; margin-top: .3rem; background: #316dca; }}
.note {{ max-width: 75rem; color: #44546a; }}
</style></head><body>
<h1>Phase 0 ablation summary</h1>
<p class=\"note\">Primary metric is queries to first Finding. Runs without a Finding remain
censored; their budget is never substituted. Median/IQR for that metric therefore use observed
runs and always show the censor count. The blue bar visualizes median cumulative Findings.</p>
<table><thead><tr><th>Controller</th><th>Budget</th><th>First Finding coverage</th>
<th>First Finding median / IQR</th><th>Cumulative Findings median / IQR</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=DEFAULT_URL, help="SQLite connection string")
    parser.add_argument("--out", type=Path, default=Path("runs/ablation-analysis"))
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=list(DEFAULT_SEEDS),
        help="the preregistered seed values; defaults to 5000 5001 5002",
    )
    args = parser.parse_args()

    with RunStore(args.db) as store:
        results = load_results(store, args.seeds)
    summaries = summarise(results)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "ablation-summary.json").write_text(
        json.dumps(
            {
                "expected_algorithms": ALGORITHMS,
                "expected_budgets": BUDGETS,
                "expected_seeds": args.seeds,
                "runs": [asdict(result) for result in results],
                "groups": [asdict(summary) for summary in summaries],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    (args.out / "ablation-summary.html").write_text(render_html(summaries), encoding="utf-8")
    print(f"wrote {args.out / 'ablation-summary.json'}")
    print(f"wrote {args.out / 'ablation-summary.html'}")


if __name__ == "__main__":
    main()
