# Recoverly — Product Requirements & Methodology (v1)

**Status:** v1 shipped and actively maintained. This document is the methodology/spec and decisions log — for what's actually built right now, see `README.md` in this folder (§15 below records spec-level changes since v1; README's "Status" section records feature-level ones — read both, neither is complete alone).
**Author:** Kris McCabe
**Scope:** Defines what Recoverly does, the assessment methodology behind it, and the IP boundary the whole project operates within.

---

## 1. IP boundary — read this before writing a line of the assessment logic

This is non-negotiable and takes precedence over everything else in this document.

- **DR3 must never be referenced, imported, paraphrased, or "made different enough."** Not the name, not its seven-lens structure, not its scoring rubric, not its canned recommendations, not its training materials. If a future session (human or AI) is tempted to "just check DR3 for inspiration," the answer is no, full stop.
- Recoverly's assessment methodology is built **from scratch**, grounded only in the **public sources listed in §2**. Every dimension, question, and scoring approach in this document was written independently for Recoverly.
- The DDRTP-style recovery time modelling (detection → backup access → assessment → tooling → API throughput) remains an **independent re-implementation** of general recovery-time-prediction principles — not the patented algorithm, not its claim language.
- If anything in this document reads suspiciously close to a seven-stage or seven-lens structure, that's a signal to restructure it, not a coincidence to wave through.

---

## 2. Grounding sources

Recoverly's methodology draws on **public, freely-reusable frameworks** — not any single proprietary methodology:

- **NIST Cybersecurity Framework 2.0** — the six functions (Govern, Identify, Protect, Detect, Respond, Recover) provide a well-known, public-domain skeleton for organising resilience capability. Explicitly designed by NIST to be built upon.
- **NIST SP 800-34 Rev. 1** — Contingency Planning Guide for Federal Information Systems (public US government publication) — informs RTO/RPO concepts, plan structure, and testing cadence.
- **ISO 22301:2019** — Business Continuity Management Systems — informs the maturity-model structure and the "plan, do, check, act" continuous-improvement framing.
- **ISO/IEC 27031** — ICT readiness for business continuity — informs the technology-recovery-specific dimensions.
- **DRI International Professional Practices** and **BCI Good Practice Guidelines** — both publicly published bodies of BC/DR practice, used only as general orientation, not copied.
- **Generic capability-maturity concepts** (the 5-level "ad hoc → optimised" ladder popularised by CMMI) — a decades-old, public-domain pattern used across countless unrelated maturity models, not specific to any vendor or methodology.

None of the above is Salesforce-authored, confidential, or DR3-derived. All are independently citable, publicly available standards.

---

## 3. What Recoverly actually produces

Two outputs, from one assessment:

1. **A Risk Assessment** — a scored, visual breakdown of how ready the organisation actually is to detect, respond to, and recover from a data-loss incident, expressed as a maturity level overall and per-dimension.
2. **A Data Recovery Response Plan** — a generated, plain-English document tailored to the organisation's actual maturity level and the specific gaps the assessment found — not a generic template, and not the same output for every org.

The core idea: **the Response Plan a low-maturity organisation needs looks different from the one a high-maturity organisation needs.** A company with no documented backup testing needs foundational guidance ("start here"). A company that already tests quarterly needs refinement guidance ("here's what's still fragile"). Recoverly should not hand everyone the same document with their name swapped in.

---

## 4. The maturity model

Five levels, applied per-dimension and rolled up to an overall score:

| Level | Name | Characteristic |
|---|---|---|
| 1 | **Ad hoc** | Reactive only. No documented process; recovery depends on individual knowledge/heroics. |
| 2 | **Developing** | Some documentation exists, but untested, inconsistent, or not owned by anyone specific. |
| 3 | **Defined** | Documented, owned, and applied consistently — but not yet tested under realistic conditions. |
| 4 | **Managed** | Tested regularly, with metrics tracked (RTO/RPO actuals vs targets), and lessons fed back in. |
| 5 | **Optimised** | Continuously improved, integrated into change management, resilient to org changes (staff turnover, system changes) without degrading. |

This ladder is deliberately generic and public-domain in structure — the specific wording and application to data recovery is original to Recoverly.

---

## 5. Assessment dimensions

Loosely organised under the NIST CSF six functions, with DR-specific additions. Each dimension gets its own maturity score (1–5) and contributes to the overall roll-up.

**Govern**
1. **Ownership & accountability** — is there a named owner for data recovery, with authority to act during an incident?
2. **Policy & compliance alignment** — are RTO/RPO targets formally documented and tied to actual business/regulatory requirements (not guessed)?

**Identify**
3. **Data & system inventory** — is there a current map of what data lives where, and its criticality?
4. **Dependency mapping** — are upstream/downstream system dependencies documented (so recovery order is known, not improvised)?

**Protect**
5. **Backup coverage & isolation** — are backups comprehensive, and segregated from the production environment they protect (so one incident can't take out both)?
6. **Access control to recovery tooling** — is access to backup/restore capability itself properly restricted and audited?

**Detect**
7. **Monitoring & alerting** — would data loss or corruption actually be noticed quickly, or only discovered when someone goes looking?

**Respond**
8. **Incident command structure** — is there a defined structure for who does what during an incident (roles, escalation, communication), independent of who happens to be online that day?
9. **Communication plan** — is there a plan for communicating with stakeholders (internal and external, including regulatory notification where applicable) during an incident?

**Recover**
10. **Recovery procedure documentation** — are actual step-by-step recovery procedures written down, per system/data type, rather than living in one person's head?
11. **Testing cadence** — are recovery procedures actually tested (not just written), and how often?
12. **Post-incident review** — is there a formal process for capturing lessons after a real incident or test, and feeding them back into the plan?

*(12 dimensions — open to adjustment during build; the point is coverage across the full lifecycle, not a specific magic number.)*

Full question wording and per-level descriptions for all 12 dimensions are in **§6**.

---

## 6. Assessment question bank

For each dimension: the question shown to the user, then what each maturity level actually looks like in plain, recognisable terms — not a generic 1–5 scale repeated twelve times.

### Govern

**1. Ownership & accountability**
*"If data recovery were needed right now, is it clear who's actually in charge of making it happen?"*
- **1 — Ad hoc:** No one is formally responsible; whoever's available handles it.
- **2 — Developing:** Someone is informally seen as "the person," but it's not documented or backed by authority.
- **3 — Defined:** A named owner and deputy are documented, with the authority to act during an incident.
- **4 — Managed:** Ownership is documented, tested during exercises, and reviewed when the org restructures.
- **5 — Optimised:** Ownership is embedded in onboarding/offboarding and change management, so it never quietly goes stale.

**2. Policy & compliance alignment**
*"Are your RTO/RPO targets based on actual business or regulatory requirements, or best guesses?"*
- **1 — Ad hoc:** No documented targets exist at all.
- **2 — Developing:** Targets exist somewhere but were set arbitrarily, without reference to real business impact.
- **3 — Defined:** Targets are documented and were derived from a real business impact assessment.
- **4 — Managed:** Targets are reviewed periodically against changing regulatory/business requirements.
- **5 — Optimised:** Targets are a living input to strategic planning, not a static compliance artefact.

### Identify

**3. Data & system inventory**
*"Could you produce an accurate list of what data lives where, and how critical each piece is, today?"*
- **1 — Ad hoc:** No inventory exists; knowledge lives in people's heads.
- **2 — Developing:** A partial or outdated inventory exists somewhere.
- **3 — Defined:** A current, accurate inventory exists and is actively maintained.
- **4 — Managed:** The inventory is kept current with tooling assistance, not manual upkeep.
- **5 — Optimised:** Criticality classifications feed directly into backup/protection decisions automatically.

**4. Dependency mapping**
*"If one system went down, do you know everything else that would be affected, and in what order to restore things?"*
- **1 — Ad hoc:** Dependencies are not documented; they're discovered during the incident itself.
- **2 — Developing:** Some dependencies are known informally but not written down.
- **3 — Defined:** A documented dependency map exists and informs recovery sequencing.
- **4 — Managed:** The map is validated periodically against the real environment, not just written once.
- **5 — Optimised:** Dependency mapping is automated/continuously discovered, not manually maintained.

### Protect

**5. Backup coverage & isolation**
*"Are your backups both comprehensive and genuinely separated from what they protect?"*
- **1 — Ad hoc:** Backup coverage is inconsistent or unknown; no isolation from production.
- **2 — Developing:** Backups exist broadly but share infrastructure/credentials with production.
- **3 — Defined:** Backups are comprehensive and properly isolated (logically or physically) from production.
- **4 — Managed:** Isolation is regularly verified, not just configured once and assumed.
- **5 — Optimised:** Isolation is architected to withstand a compromised admin account, not just a system failure.

**6. Access control to recovery tooling**
*"Is access to backup and restore capability itself properly restricted and audited?"*
- **1 — Ad hoc:** Broad, unaudited access — anyone with general admin rights can restore or delete backups.
- **2 — Developing:** Some restriction exists but isn't consistently enforced or reviewed.
- **3 — Defined:** Access is role-based, documented, and reviewed periodically.
- **4 — Managed:** Access changes are logged and alerted on, not just reviewed after the fact.
- **5 — Optimised:** Least-privilege is enforced automatically, with anomalous access flagged in real time.

### Detect

**7. Monitoring & alerting**
*"Would data loss or corruption actually be noticed quickly, or only discovered by chance?"*
- **1 — Ad hoc:** No monitoring; issues are discovered when someone complains.
- **2 — Developing:** Some monitoring exists but doesn't specifically cover data integrity/loss.
- **3 — Defined:** Monitoring specifically covers data loss/corruption scenarios, with defined alert thresholds.
- **4 — Managed:** Alerts are tuned and tested to minimise both false positives and missed detections.
- **5 — Optimised:** Detection is continuously improved based on near-miss and post-incident learnings.

### Respond

**8. Incident command structure**
*"During an incident, is it clear who does what, regardless of who happens to be online?"*
- **1 — Ad hoc:** No structure; response is improvised by whoever notices first.
- **2 — Developing:** Roles exist informally but aren't documented or rehearsed.
- **3 — Defined:** A documented incident command structure exists, with defined roles and escalation paths.
- **4 — Managed:** The structure is rehearsed through drills, not just written down.
- **5 — Optimised:** The structure flexes appropriately to incident severity/scale, tested across multiple scenario types.

**9. Communication plan**
*"Is there a plan for who gets told what, when, during an incident — including regulators if applicable?"*
- **1 — Ad hoc:** No communication plan; messaging is improvised during the incident.
- **2 — Developing:** Informal norms exist but nothing documented or pre-approved.
- **3 — Defined:** A documented plan exists covering internal and external stakeholders, including regulatory notification where applicable.
- **4 — Managed:** Templates and pre-approved messaging exist to speed up real execution.
- **5 — Optimised:** The plan is rehearsed and adapted based on lessons from drills or real incidents.

### Recover

**10. Recovery procedure documentation**
*"Are the actual steps to recover each system/data type written down, or does recovery depend on specific people?"*
- **1 — Ad hoc:** No documented procedures; recovery depends entirely on specific individuals' knowledge.
- **2 — Developing:** Some documentation exists but is incomplete, outdated, or scattered.
- **3 — Defined:** Comprehensive, current, step-by-step procedures exist per system/data type.
- **4 — Managed:** Procedures are validated against the real environment periodically, not just written once.
- **5 — Optimised:** Procedures are kept current automatically as systems change, linked to change management.

**11. Testing cadence**
*"Are recovery procedures actually tested, and how often?"*
- **1 — Ad hoc:** Never tested; confidence is based on assumption alone.
- **2 — Developing:** Tested rarely, or only after a real incident forces it.
- **3 — Defined:** Tested on a defined, regular cadence (e.g. annually or per major change).
- **4 — Managed:** Testing includes realistic, unannounced, or adversarial scenarios, not just planned walkthroughs.
- **5 — Optimised:** Testing is continuous/automated — regular game days, chaos-engineering-style exercises.

**12. Post-incident review**
*"After a real incident or test, is there a formal process to capture lessons and act on them?"*
- **1 — Ad hoc:** No review process; incidents are forgotten once resolved.
- **2 — Developing:** Informal debriefs happen sometimes but nothing is documented or tracked.
- **3 — Defined:** A formal post-incident review process exists and produces documented actions.
- **4 — Managed:** Actions from reviews are tracked to completion and verified.
- **5 — Optimised:** Review findings feed systematically into training, tooling, and the plan itself — continuous improvement, not just documentation.

---

## 7. Path to improvement

The bridging guidance between each level, for each dimension — this is the direct source material for the Response Plan's maturity-tailored sections (§10). Low-maturity orgs get the early bridges as a checklist; high-maturity orgs get the later ones as a refinement note.

**1. Ownership & accountability**
- 1→2: Identify who's actually handling recovery today, even informally, and name them as the interim owner.
- 2→3: Document ownership formally — a named primary and deputy, with explicit sign-off on their authority to act during an incident.
- 3→4: Include the owner role in incident-response drills so it's tested, not just written down; revisit after any org restructure.
- 4→5: Fold ownership assignment into onboarding/offboarding and change-management processes so it updates itself.

**2. Policy & compliance alignment**
- 1→2: Write down whatever RTO/RPO figures are currently assumed, even if they're guesses — a documented guess beats an undocumented one.
- 2→3: Run a real business impact assessment, even a lightweight one, to replace guessed targets with ones tied to actual cost of downtime/data loss.
- 3→4: Set a review cadence (annually, or after major regulatory change) so targets don't quietly go stale.
- 4→5: Feed recovery targets into strategic/budget planning directly, rather than treating them as an isolated compliance checkbox.

**3. Data & system inventory**
- 1→2: Start a basic inventory, even a spreadsheet — capture what exists before worrying about polish.
- 2→3: Assign ownership for keeping the inventory current, and reconcile it against reality at least once.
- 3→4: Introduce tooling (discovery scans, CMDB, etc.) to reduce reliance on manual updates.
- 4→5: Link criticality classifications directly into backup/protection policy so a classification change automatically adjusts protection level.

**4. Dependency mapping**
- 1→2: After any incident or major change, write down what you discover about dependencies — build the map opportunistically if not proactively.
- 2→3: Deliberately map dependencies for your most critical systems first, and use that map to define recovery order.
- 3→4: Periodically validate the map against the real environment — architectures drift faster than documentation.
- 4→5: Adopt automated dependency-discovery tooling so the map updates itself as the environment changes.

**5. Backup coverage & isolation**
- 1→2: Get coverage consistent and comprehensive first — isolation can follow once coverage is solid.
- 2→3: Separate backup infrastructure and credentials from production — different accounts, different access paths.
- 3→4: Schedule regular verification that isolation actually holds, not just that it was configured once.
- 4→5: Architect isolation to withstand a compromised admin account specifically — assume the attacker already has legitimate-looking access.

**6. Access control to recovery tooling**
- 1→2: Restrict backup/restore access to a defined group, even if managing that group is still informal.
- 2→3: Move to role-based access with a documented review cadence.
- 3→4: Add logging and alerting on access changes, not just periodic manual review.
- 4→5: Automate least-privilege enforcement and real-time anomaly detection on recovery-tooling access.

**7. Monitoring & alerting**
- 1→2: Add basic monitoring covering the most critical systems, even without data-loss-specific tuning yet.
- 2→3: Define alert thresholds specifically for data integrity/loss scenarios, not just general uptime.
- 3→4: Tune alerts based on real incidents/near-misses to reduce false positives and missed detections.
- 4→5: Build a continuous feedback loop so detection capability improves every time something is learned.

**8. Incident command structure**
- 1→2: Write down the informal roles that already exist, even loosely.
- 2→3: Formalise a documented structure with clear escalation paths.
- 3→4: Rehearse the structure through drills, not just paper reviews.
- 4→5: Test the structure across multiple incident types/severities to confirm it flexes appropriately.

**9. Communication plan**
- 1→2: Capture the informal norms that already exist for who gets told what.
- 2→3: Document a plan covering internal and external stakeholders, including regulatory notification if applicable.
- 3→4: Pre-draft templates/messaging so real execution is faster and more consistent.
- 4→5: Rehearse the plan and adapt it based on lessons from drills or real incidents.

**10. Recovery procedure documentation**
- 1→2: Start writing down whatever recovery knowledge currently exists in people's heads, even informally.
- 2→3: Fill gaps until procedures are comprehensive and current for every system/data type.
- 3→4: Validate procedures against the real environment periodically, not just at the point they were written.
- 4→5: Link procedure updates into change management so they update automatically as systems change.

**11. Testing cadence**
- 1→2: Run a first test, even a basic one — the goal is breaking the "never tested" state.
- 2→3: Establish a defined, regular testing cadence rather than reactive/one-off testing.
- 3→4: Introduce realistic or adversarial scenarios (unannounced tests) rather than only planned walkthroughs.
- 4→5: Move toward continuous/automated testing — regular game days or chaos-engineering-style exercises.

**12. Post-incident review**
- 1→2: Start holding informal debriefs after incidents or tests, even without formal documentation yet.
- 2→3: Formalise the review process so it reliably produces documented actions.
- 3→4: Track review actions to completion and verify they were actually implemented.
- 4→5: Feed review findings systematically into training, tooling, and the plan itself.

---

## 8. Scoring methodology

- Each dimension scored 1–5 by the user, against plain-English descriptions of what each level looks like for that dimension (not just a number — a description they can recognise their organisation in).
- **Overall maturity score** = weighted average across dimensions, using an **industry preset** the user selects at the start of the assessment (decided: industry-specific weighting from day one, not a generic v1).
- **Per-dimension breakdown** shown as a simple visual (bar or radar chart) so weak spots are immediately visible, not buried in an average.
- No pass/fail threshold — the point is showing *where* the gaps are, not producing an arbitrary "you failed" verdict.

### Industry weight presets (v1 hypothesis — to refine with real usage data)

Weight scale: **1.0** standard · **1.5** elevated · **2.0** critical priority for that industry.

| Dimension | Financial Services | Healthcare | Retail / E-commerce | SaaS / Technology | Public Sector |
|---|---|---|---|---|---|
| Ownership & accountability | 1.5 | 1.5 | 1.0 | 1.0 | 2.0 |
| Policy & compliance alignment | 2.0 | 1.5 | 1.0 | 1.0 | 2.0 |
| Data & system inventory | 1.0 | 2.0 | 1.0 | 1.0 | 1.5 |
| Dependency mapping | 1.0 | 1.0 | 1.5 | 2.0 | 1.0 |
| Backup coverage & isolation | 1.5 | 2.0 | 1.0 | 1.5 | 1.5 |
| Access control to recovery tooling | 1.5 | 2.0 | 1.0 | 1.5 | 1.5 |
| Monitoring & alerting | 1.0 | 1.5 | 2.0 | 1.5 | 1.0 |
| Incident command structure | 1.5 | 1.5 | 1.5 | 1.5 | 2.0 |
| Communication plan | 2.0 | 2.0 | 1.0 | 1.0 | 1.5 |
| Recovery procedure documentation | 1.0 | 1.5 | 1.5 | 1.5 | 1.5 |
| Testing cadence | 1.5 | 1.0 | 2.0 | 2.0 | 1.0 |
| Post-incident review | 1.5 | 1.0 | 1.0 | 2.0 | 1.5 |

A **General / Other** preset (all dimensions at 1.0) covers anyone who doesn't fit a listed industry, or would rather not disclose one — the assessment must work fully without forcing an industry choice.

**Rationale sketch**, so future editing of this table isn't guesswork:
- **Financial Services** and **Healthcare** both weight Communication plan at 2.0 — regulatory notification is typically both mandatory and time-critical in both sectors, just under different regimes.
- **Retail/E-commerce** and **SaaS** both weight Testing cadence at 2.0 — uptime-driven businesses tend to have (or need) a live-testing culture, unlike compliance-driven ones where documentation often outpaces testing.
- **Public Sector** weights Ownership and Policy at 2.0 — accountability structures tend to be the binding constraint in bureaucratic organisations more than technical capability.

Industry is a **user-selected dropdown** at the start of the assessment (not inferred) — simplest, most transparent, and avoids the tool guessing wrong about a sensitive classification.

---

## 9. Output 1: The Risk Assessment

Contents:
- Overall maturity score (1–5) with plain-English interpretation of what that level means in practice
- Per-dimension scores, visualised
- The 2–3 lowest-scoring dimensions called out explicitly as priority gaps
- Plain-English explanation of *why* each low-scoring dimension matters (not just "you scored 2/5 on Backup Coverage" — explain what that gap actually exposes the org to)

---

## 10. Output 2: The Data Recovery Response Plan

This is the differentiated, maturity-aware document. Structure:

1. **Overview** — org name/context (if provided), industry preset selected, overall maturity level, date generated
2. **Roles & ownership** — who should own what, tailored to whether the org already has this defined (Level 3+) or needs to start from scratch (Level 1–2). Uses the §7 bridging guidance directly: an org at Level 2 sees the 2→3 step as its instruction, not a generic "improve ownership" note.
3. **Data & dependency summary** — pulled from the assessment answers, not re-asked
4. **Recovery targets** — RTO/RPO per system/data type. Recoverly does **not** re-run the recovery-time calculation here — it embeds the resulting numbers and verdict from the standalone downtime calculator (single source of truth for that maths) with a direct link out for anyone who wants to explore the underlying scenario interactively.
5. **Recovery procedures** — for low-maturity orgs, a foundational template to fill in; for high-maturity orgs, a gap-focused refinement note rather than a full rewrite. Same §7-driven approach as roles & ownership: the plan quotes the specific next bridge for each dimension where it's the weakest, not a full re-explanation of the whole ladder.
6. **Testing plan** — a recommended cadence and format appropriate to current maturity (e.g., Level 1–2 orgs get "start with a tabletop exercise," Level 4–5 orgs get "consider chaos-engineering-style live failure injection")
7. **Regulatory notification** — a lightweight, static section: the user's selected regime (GDPR/PDPA/HIPAA/custom/not applicable) and its stated deadline, documented as fact. Deliberately **not** a live countdown — that requires the real-time RTO figure and stays exclusively in the calculator, so the plan states the obligation while the calculator tracks it live. Keeps the plan a stable, printable document rather than something that goes stale the moment it's exported.
8. **Review cadence** — when this plan itself should be revisited

**Key design rule:** low-maturity sections should read like a checklist to build from zero; high-maturity sections should read like a peer review of what's already there. Same document structure, different depth and tone depending on the assessment result.

---

## 11. Non-functional requirements

- Single-file, dependency-free build, consistent with Recoverly's existing architecture (no new backend requirement for the core assessment)
- Plain English throughout — acronyms expanded on first use, jargon avoided except in an optional "technical detail" toggle
- British English spelling throughout
- Exportable output (PDF or print-friendly view) so the generated plan can actually leave the browser and go into a real DR binder/wiki
- Weighting is set by the selected industry preset (§8); presets are editable/inspectable, not hidden — same philosophy as the existing "Eqn. 1" editable weights in Recoverly's recovery-time model
- No storage of assessment answers server-side by default — this runs entirely client-side unless the user explicitly opts into saving

---

## 12. Scoring maths

§8 describes the approach in words; this is the actual formula.

**Overall score:**

```
weighted_average = Σ(score_i × weight_i) / Σ(weight_i)
```

Where `score_i` is the user's 1–5 answer for dimension *i*, and `weight_i` is that dimension's weight under the selected industry preset (§8). This preserves the original 1–5 scale — weights change each dimension's *influence*, not the scale itself.

**Mapping to a level label:** round `weighted_average` to the nearest whole number (standard rounding, 0.5 rounds up), clamped to 1–5, and use §4's level name. Display both — the precise decimal *and* the rounded label — e.g. "2.6 / 5 — Defined" rather than silently discarding the precision.

**Identifying priority gaps (closes a gap left open in §9):** don't just rank by lowest raw score — a low score on a low-weight dimension may matter less than a middling score on a critical one. Instead, rank by **weighted shortfall**:

```
gap_i = (5 − score_i) × weight_i
```

The 2–3 dimensions with the highest `gap_i` are the priority gaps §9 calls out. If there's a genuine tie at the cutoff, include all tied dimensions rather than arbitrarily dropping one — a real tie is information, not noise to be hidden.

### Worked example

A Financial Services org (weights per §8's table), with a plausible mixed-maturity answer set:

| Dimension | Weight | Score | Weighted (score×weight) | Gap = (5−score)×weight |
|---|---|---|---|---|
| Ownership & accountability | 1.5 | 3 | 4.5 | 3.0 |
| Policy & compliance alignment | 2.0 | 3 | 6.0 | 4.0 |
| Data & system inventory | 1.0 | 4 | 4.0 | 1.0 |
| Dependency mapping | 1.0 | 2 | 2.0 | 3.0 |
| Backup coverage & isolation | 1.5 | 3 | 4.5 | 3.0 |
| Access control to recovery tooling | 1.5 | 3 | 4.5 | 3.0 |
| Monitoring & alerting | 1.0 | 2 | 2.0 | 3.0 |
| Incident command structure | 1.5 | 2 | 3.0 | 4.5 |
| Communication plan | 2.0 | 2 | 4.0 | **6.0** |
| Recovery procedure documentation | 1.0 | 3 | 3.0 | 2.0 |
| Testing cadence | 1.5 | 2 | 3.0 | 4.5 |
| Post-incident review | 1.5 | 2 | 3.0 | 4.5 |
| **Sum** | **17.0** | | **43.5** | |

- **Overall score:** 43.5 ÷ 17.0 = **2.56** → rounds to **3 — Defined**
- **Priority gaps:** Communication plan (6.0) is the clear #1 — note it only *scored* 2, tied with four other dimensions, but Financial Services' 2.0 weight on communication (regulatory notification pressure) pushes it to the top of the list on its own. Incident command, Testing cadence, and Post-incident review tie at 4.5 for the remaining slots — a genuine three-way tie, shown as such rather than picking one arbitrarily.

This is exactly the behaviour the industry weighting in §8 was designed to produce: the *same* raw score of 2 gets treated as more urgent in some dimensions than others, depending on what actually matters for that sector.

---

## 13. UI flow

Recoverly's existing app follows a tab-based single-page structure (per its `TABS` config table). This extends that pattern rather than introducing a new one:

**Assessment tab**
- Industry preset selector at the top (dropdown, defaulting to unselected — forces a conscious choice or an explicit "General/Other" pick, per §7's note on not silently defaulting)
- All 12 dimensions shown as question cards (matching §6's wording), each with the 5 level descriptions as selectable options — a user picks the one that matches, not a bare number
- A live-updating overall score preview as the user answers, in the same "reactive, no submit button" style as the downtime calculator

**Risk Assessment tab** (populated once the assessment is complete)
- Overall score and level, prominently
- Per-dimension bar or radar chart
- Priority gaps section, using the §12 gap-ranking method, each with the "why this matters" framing from §6's question context

**Response Plan tab**
- The §10 eight-section document, generated live from the assessment answers
- Each section's guidance pulled directly from §7's bridging steps for that dimension's current level
- RTO/RPO section embeds figures from the standalone calculator (linked, not recalculated — per the §10/§15 decision)
- Export/print button, since a plan that can't leave the browser doesn't make it into a real DR binder

---

## 14. Technical architecture / data model

Following the existing `App.jsx` convention (module-level config tables → pure helper functions → `App()` component → small components → CSS), the new content slots in as:

**New config tables:**
- `MATURITY_DIMENSIONS` — array of 12 objects: `{ id, category, question, levels: [{ level, name, description }] }` (5 entries per dimension, from §6)
- `MATURITY_BRIDGES` — keyed by dimension id, 4 entries each: `{ from, to, guidance }` (from §7)
- `INDUSTRY_WEIGHTS` — keyed by industry id, each an array/object of 12 weights (from §8)
- `MATURITY_LEVELS` — the 5 generic level names (from §4), reused wherever a level needs a label

**New pure helper functions:**
- `computeMaturityScore(scores, weights)` → `{ weightedAverage, roundedLevel, priorityGaps }`, implementing §12's formulas exactly
- `buildResponsePlan(scores, industry, computedScore, rtoRpoFigures)` → assembles the §10 document structure, pulling bridging guidance from `MATURITY_BRIDGES` for whichever dimensions the priority-gaps logic flagged

**Data flow:** assessment answers live in component state (no server round-trip, per §11's "no storage by default"); `computeMaturityScore` and `buildResponsePlan` are both pure functions of that state, so the Risk Assessment and Response Plan tabs are just different renderings of the same underlying computation — not two independent code paths that could drift apart.

---

## 15. Decisions log

Settled during requirements review — kept here so the reasoning isn't lost, not just the outcome.

| Decision | Outcome | Rationale |
|---|---|---|
| Dimension weighting | **Industry-specific from day one** | The 12 dimensions don't matter equally across sectors (see §8 table) — a generic-then-refine approach risked shipping a v1 that felt wrong for the exact audience most likely to try it first. |
| Assessment scope | **Single system per run (v1)** | Keeps the tool focused and shippable. "System" means one clearly-bounded unit — one Salesforce org, one application and its data store, or one defined business process's data. Multi-system/portfolio-level aggregation is a deliberate v2+ deferral, not an oversight. |
| DDRTP-style recovery-time integration | **Link out, don't duplicate** | The Response Plan embeds the resulting numbers and verdict from the standalone calculator rather than re-implementing the calculation. One source of truth for the maths avoids the two copies drifting apart the next time either gets fixed. |
| Regulatory notification section | **Lightweight static version, embedded** | The plan states the selected regime and its deadline as fact (not a live countdown, which stays in the calculator). Balances making the plan feel complete against the risk of a formal-looking document implying more legal authority than a disclaimer alone can offset. |

### New questions this raised (not yet settled)

- The industry weight table in §8 is a first-pass hypothesis, not tested against real assessments — worth revisiting once a handful of people have actually used it.
- "Not disclosing an industry" defaults to the General/Other preset (equal weighting) — worth confirming that's the right silent default versus prompting the user to at least acknowledge they're skipping it.

### Post-v1 additions (not in the original §10 spec)

*These are spec/structure changes to the Response Plan itself. For feature-level additions (editable weights, multi-assessment support, calculator handoff, exports, tests) see README.md's "Status" section instead — the two lists don't overlap, and neither is a complete picture on its own.*

Prompted by reviewing a competitor's (Cutover's) public DR-planning guide for gaps — no content or structure copied, just used to sanity-check completeness against generic, industry-standard DR planning concepts:

- **Plan ownership & revision history** — a new Preparation-group section distinct from Roles & ownership; tracks who maintains the *document* (not who runs a live recovery) and a running log of changes/approvals.
- **Incident scope** — "what kinds of incidents does this plan cover" added to Data & dependency summary.
- **Stall escalation** — Recovery execution now asks who gets escalated to if recovery runs past MTD, tying the Response Plan back to the Business Continuity Tolerance concept from the downtime calculator.
- **Real-incident post-mortem** — Review cadence (renamed "Review & lessons learned") now distinguishes a real incident's post-mortem findings from routine test results, which previously had no home.
- **Response Plan is now an accordion** (native `<details>`/`<summary>`, first section per group open by default) rather than one long scroll — PDF/Word export unaffected since both build from `state` directly, not from whatever's expanded on screen.
- **Removed the Paged.js paginated-PDF attempt** from the previous session — it rendered blank in practice and isn't debuggable without a real browser. PDF export is back to plain, reliable printing of the full content (including the "your 12 answers" record, which is a genuine keeper from that attempt).
- **Application isolation fields** added to Recovery execution: application access/permissions (distinct from backup-tool access), automation to deactivate during recovery, integrations to suspend, notifications to disable, and known complexities — the kind of practical detail that quietly derails real recoveries (automation firing on half-restored data, customers getting confusing notification emails, integrations corrupting both sides of a sync).
