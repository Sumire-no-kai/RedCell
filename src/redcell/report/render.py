"""报告渲染:JSON 与单文件 HTML。

HTML 刻意做成**完全自包含**(样式内联、无外部资源):
报告会被邮件转发、附在工单里、离线打开,任何外链在那些场景下都会失效,
而一份样式全丢的安全报告很容易被误读。
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment

from redcell.report.model import ReportData

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>RedCell report — {{ d.run.target_name }}</title>
<style>
 body{font:15px/1.6 system-ui,sans-serif;margin:0;padding:2rem;max-width:60rem;
      color:#1a1a1a;background:#fff}
 h1{font-size:1.6rem;margin:0 0 .25rem} h2{font-size:1.15rem;margin:2rem 0 .5rem;
      border-bottom:1px solid #e5e5e5;padding-bottom:.3rem}
 .sub{color:#666;margin:0 0 1.5rem}
 table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.9rem}
 th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eee}
 th{background:#fafafa;font-weight:600}
 .kv{display:grid;grid-template-columns:auto 1fr;gap:.2rem 1rem;font-size:.9rem}
 .kv dt{color:#666} .kv dd{margin:0}
 .note{background:#fff8e6;border-left:3px solid #e0a800;padding:.7rem 1rem;
       margin:1rem 0;font-size:.9rem}
 .bad{color:#b00020;font-weight:600} .ok{color:#0a7d33}
 .unknown{color:#8a6d00;font-weight:600}
 code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;font-size:.85em}
 .ev{font-size:.85rem;color:#444;margin:.2rem 0 .2rem 1rem}
</style></head><body>

<h1>RedCell — {{ d.run.target_name }}</h1>
<p class="sub">{{ d.run.algorithm }} · {{ d.total_attempts }} attempts ·
   generated {{ d.generated_at.strftime('%Y-%m-%d %H:%M UTC') }}</p>

<h2>Summary</h2>
<dl class="kv">
  <dt>Findings</dt><dd>{{ d.findings|length }}</dd>
  <dt>Impact realized</dt><dd class="{{ 'bad' if d.impact.realized else 'ok' }}">
      {{ d.impact.realized }}</dd>
  <dt>Attempted but blocked</dt><dd>{{ d.impact.not_realized }}</dd>
  <dt>Impact unverifiable</dt><dd class="{{ 'unknown' if d.impact.unknown else '' }}">
      {{ d.impact.unknown }}</dd>
  <dt>Queries to first Attempt success</dt>
  <dd>{{ d.queries_to_first_attempt_success
      if d.queries_to_first_attempt_success else 'never succeeded' }}</dd>
  <dt>Queries to first Impact success</dt>
  <dd>{{ d.queries_to_first_impact_success
      if d.queries_to_first_impact_success else 'never succeeded' }}</dd>
  <dt>Stopped by</dt><dd>{{ d.run.stopped_by.value if d.run.stopped_by else '—' }}</dd>
</dl>

{% if not d.run.is_conclusive %}
<div class="note"><strong>This run did not complete ({{ d.run.status.value }}).</strong>
 An interrupted run under-counts findings, so these numbers must not be compared
 against completed runs.</div>
{% endif %}

{% if d.impact.unknown %}
<div class="note"><strong>{{ d.impact.unknown }} finding(s) have unverifiable impact.</strong>
 The target's observability was insufficient to tell whether the action actually
 took effect. These are neither confirmed nor safe — they need manual review.</div>
{% endif %}

<h2>Scope &amp; method</h2>
<dl class="kv">
  <dt>Adapter</dt><dd><code>{{ d.run.adapter_type }}</code></dd>
  <dt>Policy version</dt><dd><code>{{ d.run.policy_version }}</code></dd>
  <dt>Target model</dt><dd><code>{{ d.run.target_model or '—' }}</code></dd>
  <dt>Temperature</dt>
  <dd>{{ d.run.target_temperature if d.run.target_temperature is not none else '—' }}</dd>
  <dt>Seed</dt><dd>{{ d.run.seed if d.run.seed is not none else '—' }}</dd>
  <dt>Budget</dt><dd>{{ d.run.limits.max_attempts or '—' }} attempts ·
      {{ d.run.limits.max_total_tokens or '—' }} tokens ·
      {{ d.run.limits.max_cost_usd or '—' }} USD</dd>
  <dt>Used</dt><dd>{{ d.run.usage.attempts }} attempts ·
      {{ d.run.usage.total_tokens }} tokens ·
      {{ '%.4f'|format(d.run.usage.cost_usd) }} USD</dd>
</dl>

<h2>Budget allocation by strategy</h2>
<table><tr><th>Strategy</th><th>Attempts</th><th>Share</th>
 <th>Attempt hits</th><th>Attempt ASR</th>
 <th>Impact hits</th><th>Impact ASR</th><th>Mean signal score</th></tr>
{% for s in d.strategy_stats %}
 <tr><td><code>{{ s.strategy_id }}</code></td><td>{{ s.attempts }}</td>
  <td>{{ '%.0f%%'|format(100 * d.budget_share.get(s.strategy_id, 0)) }}</td>
  <td>{{ s.attempt_hits }}</td>
  <td>{{ '%.0f%%'|format(100 * s.attempt_success_rate) }}</td>
  <td>{{ s.impact_hits }}</td>
  <td>{{ '%.0f%%'|format(100 * s.impact_success_rate) }}</td>
  <td>{{ '%.2f'|format(s.mean_signal_score) }}</td></tr>
{% endfor %}
</table>

<h2>Findings</h2>
{% if not d.findings %}<p>No findings.</p>{% endif %}
{% for f in d.findings %}
 <p><strong>{{ loop.index }}. {{ f.title }}</strong><br>
  <code>{{ f.category.value }}</code> · actor <code>{{ f.actor }}</code> ·
  strategy <code>{{ f.strategy_id }}</code> ·
  impact <span class="{{ 'bad' if f.triad.realized_impact.value == 'realized'
       else ('unknown' if f.triad.realized_impact.value == 'unknown' else 'ok') }}">
   {{ f.triad.realized_impact.value }}</span>
  {% if f.reproduction_rate is not none %}
   · reproduced {{ '%.0f%%'|format(100 * f.reproduction_rate) }}
   of {{ f.reproduction_runs }}{% endif %}</p>
 {% if f.impact_caveat %}<div class="note">{{ f.impact_caveat }}</div>{% endif %}
 {% for e in f.evidence %}<div class="ev">▸ {{ e.description }}
  {% if e.matched_value %}— <code>{{ e.matched_value }}</code>{% endif %}</div>{% endfor %}
 {% if f.recommended_mitigation %}<div class="ev">→ {{ f.recommended_mitigation }}</div>{% endif %}
{% endfor %}

<h2>Limitations</h2>
<div class="note">{{ d.disclaimer }}</div>

</body></html>
"""


def to_json(data: ReportData, *, indent: int = 2) -> str:
    return json.dumps(data.model_dump(mode="json"), indent=indent, ensure_ascii=False)


def to_html(data: ReportData) -> str:
    env = Environment(autoescape=True)
    return env.from_string(_TEMPLATE).render(d=data)


def write_report(data: ReportData, directory: Path, *, stem: str = "report") -> dict[str, Path]:
    """两种格式一起写。

    JSON 供机器消费(回归测试、聚合分析),HTML 供人阅读 ——
    只出其中一种,总有一边不好用。
    """
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": directory / f"{stem}.json",
        "html": directory / f"{stem}.html",
    }
    paths["json"].write_text(to_json(data), encoding="utf-8")
    paths["html"].write_text(to_html(data), encoding="utf-8")
    return paths
