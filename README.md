# lab-tools

Source for `lab.krismccabe.com` — independent tools and experiments in
data resilience, Salesforce architecture, and AI.

## Structure

```
kris-lab/
├── index.html              — lab landing page
├── recoverly/               — data recovery maturity assessment (see its own README — source lives in a separate repo)
├── redline/                 — RTO/RPO "true cost of downtime" calculator
├── schema-explorer/         — Salesforce cascade-delete/orphan/blocker impact visualiser
├── tabletop/                — live, branching Incident Command practice exercise
├── drillmaker/              — HSEEP-aligned Master Scenario Events List (MSEL) generator
├── traceability/            — multi-system dependency graph → topological recovery sequencer
├── ai-shield/               — AI security & trust maturity assessment
├── flare/                   — live AI/LLM library vulnerability tracker (OSV.dev data)
├── agent-impact/            — AI agent Blast Radius / Irreversibility simulator & guardrail policy exporter
└── schemas/                 — published JSON Schemas referenced by exported tool output (e.g. agent-impact-guardrail.v1.json)
```

Every tool here is a static, dependency-free page — no build step, no
backend, no database. New tools get their own folder with an `index.html`,
plus a card added to the root `index.html` landing page. Every tool page
should include a "← Back to Kris's Lab" header linking to `/`, matching
the pattern in `redline/index.html` — no tool should be a
dead end.

Several tools hand off real, computed data to each other via URL query
parameters rather than just linking (Redline → Recoverly, Drillmaker →
Tabletop, Traceability → Redline) — if you add a new handoff, the
receiving tool needs actual logic to read and use the params, not just a
link that carries an unused query string.

## Deploy

Deployed via `wrangler deploy` (Cloudflare Workers Static Assets) on
every push to `main` — no build command needed (static asset directory:
`/`). A `.assetsignore` file excludes specific files from the deployed
bundle (currently internal docs meant for repo/GitHub access only, not
public pages). If you ever add a `_redirects` file, note that only status
codes `200/301/302/303/307/308` are valid here — `404` is not, and using
it will fail the deploy outright.

## What this is (and isn't)

Independent projects, built on personal time using general, public
principles. Not affiliated with, endorsed by, or built using confidential
material from any employer, past or present.

## Feedback

Spotted a bug, got an idea, or found something that made you go "hmm"?
Please [open an issue](../../issues) — all feedback is very welcome.
