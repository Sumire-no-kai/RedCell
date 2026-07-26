# Security Policy

RedCell is a security-testing tool. That makes the boundary between "a bug in
RedCell" and "a vulnerability RedCell is supposed to find" unusually easy to blur,
so this document states it explicitly.

## Reporting a vulnerability

Report privately via GitHub's
[private security advisory](https://github.com/Sumire-no-kai/RedCell/security/advisories/new)
form. Please do **not** open a public issue for a suspected security problem.

A useful report includes the affected version or commit, what an attacker gains,
and the smallest reproduction you can manage. This is a personal project, not a
funded one — expect an initial reply within about a week, and please allow time
for a fix before disclosing publicly.

## In scope

- Sandbox escape: anything that lets a benchmark target or a generated attack
  payload execute code, touch the filesystem, or reach the network outside the
  intended boundary.
- Leakage of user secrets — API keys, credentials, or `.env` contents ending up in
  traces, findings, reports, exported regression tests, or logs.
- Any code path that performs a real-world side effect (payment, deletion, email,
  cloud API call) instead of going through the simulated tool layer.
- Bypassing the per-run query, token, or cost budget.
- Cross-project leakage of traces or findings.
- Dependency vulnerabilities with a plausible exploitation path in this codebase.

## Out of scope

**Vulnerabilities in the bundled Arena agents.** The Arena ships deliberately
vulnerable tool-using agents — embedded canaries, permissive system prompts,
cross-tenant readable records, forbidden tools that are reachable through social
engineering. These are ground truth for the benchmark, not defects. Finding them
means RedCell is working.

Also out of scope: findings produced by running RedCell against your own systems
(report those to whoever owns the system); false positives or false negatives from
the scoring engine (open a normal issue — accuracy is tracked, but it is a quality
matter, not a vulnerability); and attacks that require an already-compromised local
machine.

## Using RedCell safely

RedCell is for authorized, defensive testing only — see the Authorization &
Ethical Use notice in the [README](README.md). Run it against targets you own or
have written permission to test. Tool execution defaults to simulation; the
project ships no connectors that attack real production systems, and adding one
would itself be out of scope for contributions.
