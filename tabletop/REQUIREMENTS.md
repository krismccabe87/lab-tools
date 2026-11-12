# Tabletop — Requirements & Methodology

**Status:** Documented retroactively from the shipped implementation (6 commits, current build) — this is an as-built spec, not a forward design doc.
**Source:** `tabletop/index.html`
**Scope:** What Tabletop does, the scenario/branching model it's built on, the scoring mechanics, and what it deliberately does not attempt.

---

## 1. Grounding & IP boundary

- Grounded entirely in the **Incident Command System (ICS) / NIMS** — a public-domain emergency-management framework, explicitly noted in the tool's own footer as already widely adapted into tech incident response by Google SRE, Atlassian, and PagerDuty. Not derived from any employer's internal or proprietary methodology.
- Deliberately **business-level narrative only, no technical exploit detail** (stated at the top of the scenario bank in code) — scenarios are about decision-making and coordination, not technical war-gaming.
- Explicitly framed as **practice, not a real plan**: "This is a practice exercise, not a real incident response plan — pair it with Recoverly's Response Plan for the real thing." Tabletop and Recoverly are positioned as complementary, not overlapping.

---

## 2. What Tabletop produces

A live, single-session, role-played tabletop exercise:
1. Pick one of 12 incident scenarios.
2. Assign the 4 ICS core roles to real people in the room (names are session-local only, never saved).
3. Work through 6 fixed ICS-aligned stages, making one decision per stage from a shuffled set of options with immediate, quality-specific consequences shown before moving on.
4. Answer one self-report rubric item.
5. Get a percentage score, a qualitative tier, and (optionally) save the run to a local, opt-in run history that surfaces recurring weaknesses across sessions — the one thing no single run can show on its own.

---

## 3. Scenario bank

12 scenarios total, in two difficulty bands:
- **Foundational (6):** Silent data corruption, Accidental mass deletion, Ransomware-style encryption event, Platform region outage, Failed deployment discovered late, Insider error / account compromise ambiguity.
- **Complex (6, added later):** Vendor breach cascade, Insider-or-compromised ambiguity, Fix makes it worse, Slow-burn repeat incident, Legal hold conflict, Multi-region ambiguity — each built with a **second complication mid-exercise**, not just one, to escalate realism further than the foundational set.

Each scenario defines:
- `id`, `name`, `desc` (one-line card summary), `difficulty`.
- `trigger` — the opening narrative shown at Stage 1.
- `clock` — the ticking-clock pressure element, reused as the Stage 3 narrative base.
- `complication` — a mid-exercise twist revealed at Stage 3, simulating how real incidents evolve messily rather than neatly.
- `decisionOverrides` — a map keyed by stage index (0–5), each providing 4 scenario-specific decision options that replace the generic stage decisions. All 12 scenarios now have overrides for all 6 stages (confirmed complete per commit history: *"Complete scenario-specific decisions for all 12 scenarios across all 6 stages"*) — scenario-specific decisions take priority when defined, falling back to generic ICS decisions otherwise, which let scenarios be authored incrementally rather than requiring every stage up front.

---

## 4. The 6 fixed stages

`STAGES` mirrors the real ICS lifecycle, not an arbitrary sequence:

| # | Label | ICS concept |
|---|---|---|
| 1 | Notification & initial size-up | Verifying scope before reacting |
| 2 | Establish Incident Command | Naming a single Incident Commander, always first, last to stand down |
| 3 | New information changes the picture | Re-briefing when facts shift; complication reveal happens here |
| 4 | Develop the Incident Action Plan | Objectives, tactics, communications plan — set by Command, not improvised |
| 5 | Operations executes the plan | Turning objectives into tactical action, separate from the command decision |
| 6 | Demobilization & After-Action Review | Two distinct deliberate steps: standing down, then a structured review |

Each stage carries: a `narrative` function (scenario- and path-aware, see §6), a `decisionPrompt`, 4 generic fallback `decisions`, an optional `complication` hook (used at Stages 3 and 5), and a standalone `recommendation` string used in the closing tier note.

---

## 5. Decision model

Every decision (generic or scenario-specific) has:
- `lead` — a short bolded label (e.g. "Name one IC").
- `text` — the full description of the action.
- `quality` — one of `strong` / `mixed` / `weak` / `harmful`.
- `consequence` — shown immediately after selection, before the next stage.

**Shuffling:** each stage's decision order is randomised per session via Fisher-Yates (`shuffledIndices`), generated once per stage and cached for the session. This exists specifically so that anyone who runs the exercise more than once, or compares notes with someone who has, can't just learn "always pick the first option" without engaging with the actual reasoning — a deliberate anti-gaming measure, not cosmetic randomness.

Once a choice is made for a stage, the other three options dim (not hidden) and become non-interactive — the choice is visible and final for that run.

---

## 6. Branching narrative

`precedingPathState(stageIndex)` determines each stage's narrative variant based on **the immediately preceding stage's decision quality only** — not a running average across the whole exercise:
- Preceding `strong` → **steady** (default narrative).
- Preceding `mixed` → **mixed** narrative variant.
- Preceding `weak` or `harmful` → **strained** narrative variant (the two qualities are deliberately collapsed into one branch).

This is genuine branching, not a cosmetic label: a single bad call visibly changes what the *next* stage's setup narrative says, rather than being smoothed away by otherwise-good choices elsewhere in the run. Collapsing weak+harmful into one "strained" branch was a deliberate content-authoring tradeoff — it keeps each stage to 3 narrative variants instead of 4, while the *scoring* still tells weak and harmful apart (see §7). When the path is strained, a visible warning banner appears above the stage ("Your response so far has had more rough edges than usual — this stage reflects that, not a separate penalty").

---

## 7. Scoring

```
QUALITY_POINTS = { strong: 1, mixed: 0.6, weak: 0.2, harmful: 0 }
```

- `earned` = sum of `QUALITY_POINTS` across all 6 stage choices, **plus 1 point** if the single rubric item (§8) is checked.
- `totalPossible = STAGES.length + 1 = 7`.
- `percentage = round(earned / totalPossible * 100)`.

This deliberately replaces pure self-report scoring with something driven by the team's actual in-exercise decisions and their visible consequences — the rubric item exists only for the one thing a discrete multiple-choice decision genuinely can't capture (whether the room's language stayed plain and shared throughout).

**Score tiers** (`scoreTier`), each with a fixed narrative note rather than just a number:
| Range | Label | Note |
|---|---|---|
| 100% | Strong | "Well-run by ICS standards — the value of a drill here is keeping it sharp, not fixing it." |
| ≥75% | Solid, with specific gaps | "Core discipline is mostly there — close these before a real incident, not this drill." |
| ≥50% | Developing | "Several foundational ICS practices weren't in place — pick one or two gaps to focus on, not all at once." |
| <50% | Needs work | "Most of the core discipline wasn't demonstrated — start with naming a single Incident Commander; most of the rest follows from that one decision." |

---

## 8. Rubric

`RUBRIC` currently holds **exactly one item**: *"The team used plain, clear language — not jargon only some people in the room understood,"* grounded explicitly in ICS's own "common terminology" principle, with its own "why this matters" text and a bridging recommendation. It's structured as an array specifically so more self-report items could be added later without changing the scoring logic — currently a single-item array, not yet expanded.

---

## 9. Run history

Opt-in only, via an explicit "Save this run" action — never silent, matching the same pattern already used elsewhere in the lab (Schema Explorer's saved-schema toggle, Recoverly's saved-assessments). Stored in `localStorage` under `tabletop_run_history_v1`.

Each saved run records: `timestamp`, `scenarioId`, `scenarioName`, `difficulty`, `score`, the full array of per-stage `quality` values, and whether the terminology rubric item was checked. Notably: **role names and stage notes are never included** in the saved record — only the score-relevant data.

`renderHistorySummary()` shows, once at least one run is saved:
- Total run count and average score.
- A bar-chart trend view (`trend-bars`) — one bar per run, height proportional to that run's score relative to the team's best run.
- **Cross-run weakness detection** — for each of the 6 stages, the fraction of saved runs where that stage scored anything other than `strong`. The single worst stage is surfaced as a "recurring pattern" flag, but only if **at least 2 runs share that stage** (so a single fluke can't masquerade as a pattern) **and** it scored non-strong in ≥50% of those runs. This is presented explicitly as "the part a single run's score can never show on its own" — the whole reason the history feature exists, not an incidental add-on.
- A one-click "Clear history" action.

---

## 10. Roles

4 fixed ICS core roles, captured as free-text name inputs for the room's own reference during the session:
- Incident Commander
- Operations Lead
- Public Information Officer (Comms)
- Planning / Documentation Lead

Explicitly stated in the UI: "Names are just for this session — nothing is saved anywhere" — and confirmed by §9, where saved run history excludes them entirely.

---

## 11. UI flow

Scenario panel → Roles panel → Exercise panel (stage-by-stage: narrative → optional complication box → decision prompt → decision cards → consequence → optional notes textarea → Back/Next) → Rubric panel → score/tier result with save-to-history option. Progress is shown via a row of stage-marker dots (done / current / upcoming). Back navigation is supported mid-exercise; notes per stage are retained in memory across navigation but not persisted anywhere.

**No PDF/print/markdown export exists for a completed run** — unlike both Recoverly (PDF/Word export) and Schema Explorer (CSV/Markdown export), a finished Tabletop session's decisions, consequences, and notes cannot leave the browser except via the opt-in score-only history entry. Anyone wanting a record of the qualitative narrative/consequences/notes for a real after-action review currently has to copy them manually.

---

## 12. Non-functional requirements

- Single-file, dependency-free, consistent with the rest of the lab — no build step, no backend.
- No server-side storage, ever. `localStorage` use (run history only) is opt-in and explicit.
- Role names and stage notes exist only in page memory for the current session — never written to `localStorage`, never transmitted.
- British English spelling throughout.
- Deliberately business-level, non-technical scenario writing (§1) — a constraint on tone and content, not just a style preference.

---

## 13. Decisions log

Reconstructed from commit history, kept here so the reasoning isn't lost:

| Decision | Outcome | Rationale |
|---|---|---|
| Tool name | **Renamed from "Standdown" to "Tabletop" early** (`d42d5bd`) | Naming clarity — "Tabletop exercise" is the standard, recognisable term for this kind of practice drill; "Standdown" doesn't communicate that on its own. |
| Decision option ordering | **Shuffled per stage, per session (Fisher-Yates)** | Prevents position-memorisation from defeating the exercise's actual point across repeat plays or shared notes between colleagues. |
| Narrative branching basis | **Immediately preceding stage's quality only, not a running average** | Keeps consequences legible and directly traceable to a specific decision, rather than smoothed away by an aggregate. |
| Weak/harmful narrative collapse | **Share one "strained" narrative branch, but score separately** | Keeps authored content tractable (3 narrative variants per stage instead of 4) without losing scoring resolution between the two quality levels. |
| Run history | **Opt-in, score-only, added after the base exercise shipped** | Surfaces cross-run patterns (a stage that's *always* weak) that no single run's result can reveal — deliberately excludes role names/notes, which aren't needed for that purpose and are more sensitive to retain. |
| Scenario complexity growth | **6 foundational scenarios shipped first; 6 "complex" scenarios with a genuine second complication added later** | Let a complete, working exercise ship before the harder authoring lift of realistic multi-complication escalation. |

---

## 14. Known gaps (open items, not yet decided)

- No export of a completed run's narrative/consequences/notes (see §11) — score-only history is the only thing that survives a session.
- `RUBRIC` has held exactly one item since inception — worth a deliberate decision on whether that's the intended final scope (one thing decisions genuinely can't capture) or a placeholder that should grow.
- Unlike Recoverly's industry-weighted maturity model, Tabletop's scoring treats all 6 stages equally regardless of scenario or organisation type — not necessarily wrong, but an explicit design asymmetry between the lab's two "scored assessment" tools worth being aware of if either evolves further.
- No dark mode / `prefers-color-scheme` handling, consistent with the rest of the lab.
