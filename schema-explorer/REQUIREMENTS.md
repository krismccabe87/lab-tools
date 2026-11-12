# Schema Explorer — Requirements & Methodology

**Status:** Documented retroactively from the shipped implementation (24 commits, current build) — this is an as-built spec, not a forward design doc.
**Source:** `schema-explorer/index.html`
**Scope:** What Schema Explorer does, the relationship model it's built on, the import/diagram/scoring mechanics, and the boundaries of what it can honestly claim to know.

---

## 1. Grounding & IP boundary

- The tool models **default, out-of-the-box Salesforce platform behaviour** — publicly documented via Salesforce's own object reference docs and the `describe()` API (`cascadeDelete`, `restrictedDelete` flags on `Schema.ChildRelationship`). Nothing here is proprietary or vendor-confidential.
- Explicitly **not affiliated with or endorsed by Salesforce** (stated in the footer disclaimer).
- The "own org" import path uses only the user's **own already-authenticated session** or their own Apex debug logs — no login form, no credentials requested or stored, no third-party relay. This is a deliberate, repeated design constraint (see §5).

---

## 2. What Schema Explorer produces

One core question, answered visually and in text: **"If I delete one record of this type, what happens to everything connected to it?"**

For a chosen object and a chosen traversal depth, it returns three categorised outcomes:
1. **Cascade-deleted** — child records that are permanently destroyed along with the parent.
2. **Orphaned** — child records that survive, but the reference field pointing at the deleted parent is cleared.
3. **Restricted (deletion blockers)** — relationships that prevent the parent from being deleted at all while the child exists.

Presented two ways (user-selectable): a radial relationship diagram, or a collapsible tree list grouped by outcome.

---

## 3. Data model

**`OBJECTS`** — flat array of `{ id, label, category }`. ~300 Salesforce standard objects across categories: Sales, Service, Marketing, Product Catalogue, Activities, Files & Content, Chatter, Platform, Order Management, Workforce Engagement, Partner & Channel, Field Service, and "Industry Clouds (verify against your org)" for Health Cloud / Financial Services Cloud objects. A "From your org" category is added dynamically the first time a user imports custom data.

**`RELATIONSHIPS`** — flat array of `{ child, parent, type }`. `type` is one of:
| Type | Meaning |
|---|---|
| `master-detail` | True Master-Detail — always cascades, child cannot exist without parent |
| `account-cascade` | A lookup field Salesforce hard-codes to cascade-delete specifically when the parent Account is removed — a documented platform quirk distinct from ordinary lookup behaviour |
| `lookup` | Standard behaviour — deleting the parent clears the child's reference field; the child survives |
| `restricted` | Deletion of the parent is blocked while this child relationship exists |
| `org-cascade` | Cascade behaviour confirmed via a user's own imported `describe()`/debug-log data, not the built-in reference model |

`CASCADE_TYPES = ['master-detail', 'account-cascade', 'org-cascade']` — the set treated as "this deletes" for traversal and colouring purposes.

**Confidence tiers, by design, not uniform:**
- Core Sales/Service objects: relationship type is a specific, considered judgement call (master-detail vs. account-cascade vs. lookup).
- Objects sourced from Salesforce's official object reference PDF batch (~229 objects: Order Management, Product Catalogue, Workforce Engagement, Partner & Channel): relationship *existence* is sourced from that document, but the document itself labels every reference field as generic "Lookup" even where the tool's author independently knows some cascade in practice (e.g. `CaseComment`, `OpportunityLineItem`). Rather than guess, these default to `lookup` uniformly — an honest under-claim, not a verified one.
- Industry Cloud objects (Health Cloud, Financial Services Cloud): object *names* are verified against official docs, but relationships are **deliberately not modelled at all** — shown with an explicit "low confidence" banner rather than a silent empty result.
- Objects present in `OBJECTS` with no entry in `RELATIONSHIPS` are an honest "not yet covered" gap (documented inline), not a claim that no relationships exist.

---

## 4. Impact algorithm

`findImpact(objectId, maxDepth)` — depth-limited recursive traversal from the target object:
- Cascade relationships (`CASCADE_TYPES`) recurse further (their children can themselves cascade-delete downstream records); lookup and restricted relationships are recorded but not traversed past.
- **Cascade always wins.** If a child is reachable via both a cascade path and a lookup/restricted path (through different parents), it's classified as cascade-deleted — this was a specific bug fix (see §11), not the original behaviour.
- Each result records the relationship that caused it and the depth at which it was found.
- `maxDepth` is user-controlled via a slider, 1–10, default 2. "1" is direct relationships only; higher values follow cascade chains further (e.g. Account → Opportunity → Quote → Quote Line Item is 3 deep). Most real cascades are shallow, so this mainly matters for long chains or large imported org schemas.

---

## 5. Own-org data import

Two accepted input formats, both parsed by `importSchemaText()`:

1. **`describe()` JSON** — a single object or array of objects, each with `.name`, `.label`, `.childRelationships[]` (using `cascadeDelete`/`restrictedDelete` flags directly). Obtainable from a browser tab already logged into the user's sandbox, hitting `/services/data/vNN.0/sobjects/{Object}/describe/` directly — no separate login.
2. **Line-based Apex debug log format** (`SCHEMA|OBJ|...` / `SCHEMA|REL|...`) — deliberately chosen over JSON for org-wide exports specifically because **Apex debug logs have a size limit and can truncate mid-export**. A cut-off JSON payload is structurally unparseable in its entirety; a cut-off line-based format only loses its last incomplete line. The provided Apex script defaults to custom objects only (`includeStandardObjects = false`) since standard objects are already covered by the built-in model.

Import behaviour:
- Real debug log exports carry a timestamp/context prefix before the actual message — the parser searches for `SCHEMA|` anywhere in the line rather than assuming it starts one.
- Salesforce's downloaded log files HTML-encode the literal pipe character as `&#124;`, silently breaking every marker if not decoded first — this is decoded (along with `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`/`&apos;`) before any other parsing.
- New objects are added under a "From your org" category; new relationships are appended, existing ones (same child+parent) are updated in place and flagged `imported: true`.
- Imported cascade relationships are uniformly mapped to `org-cascade` — real Salesforce data only distinguishes `cascadeDelete` / `restrictedDelete` / neither, with no signal for *why* something cascades, so that finer distinction (which the built-in model does make) can't be reconstructed from imported data.
- **Error handling is deliberately diagnostic, not generic:** empty input, unparseable text that still looks like a genuine Apex debug log (detected via markers like `EXECUTION_STARTED`, `USER_DEBUG`) gets a specific fix ("your debug level is filtering out `System.debug()` output — raise Apex Code logging to DEBUG"), versus unparseable text that isn't a log at all ("that doesn't look like valid JSON or SCHEMA| lines").
- Optional persistence: a checkbox opts into saving the imported schema to `localStorage` (key `schemaExplorer_savedCustomSchema_v1`) so it survives a page reload; a visible badge shows when saved data is active, with a one-click "Clear Saved Schema" action. `localStorage` failures (private browsing, quota) fail silently with a console warning rather than breaking the import that already succeeded.
- Drag-and-drop, click-to-browse, or paste-as-text are all supported, all client-side via `FileReader` — nothing is ever uploaded anywhere.

---

## 6. Live Salesforce API version check

The one network call anywhere in the lab: a `fetch()` to `https://test.salesforce.com/services/data/` (the **sandbox login domain specifically, never production**) to display the current Salesforce API version. This is expected to frequently fail (no CORS headers permitting a browser at this origin), and degrades honestly:
- Success: "checked live just now via test.salesforce.com."
- Failure: falls back to a manually verified, hardcoded value (currently v67.0 / Summer '26), with UI copy explicitly stating the live check failed and why (likely CORS), rather than silently presenting a stale value as current.

---

## 7. UI / interaction model

- **Object picker:** category tabs with live counts (`All (300)`, `Sales (142)`, etc.) plus a free-text search across label, API name, and category, operating over a scrollable, category-grouped button grid. Category tabs exist specifically because a flat wall of ~300 buttons is unusable — narrowing to one domain avoids scrolling past hundreds of irrelevant objects.
- **Depth slider:** 1–10, default 2, re-renders the current result live on change.
- **View modes:** Radial Diagram (default) or Tree List View, user-togglable per result.
- **Filter modes:** Show All / Cascade Only / Restricted (Blockers) Only — applies to both view modes.
- **Metric cards:** live counts of cascade-deleted / orphaned / blocked, plus a persistent reminder card that Recycle Bin restore does not guarantee relationships reattach.
- **Detail drawer:** clicking any node shows why that object is in *this* diagram specifically (the contextual relationship that placed it there), separately from any other known relationships elsewhere in the schema (explicitly not conflated — a generic object like `ContentDocumentLink` can have dozens of unrelated relationships in a large imported schema, and showing all of them without distinguishing "why is this here" would be actively misleading). Includes a link to Salesforce's official object reference page and a "Focus on this Object" action that re-roots the whole exploration.
- **Diagram interactivity:** mouse-wheel zoom (0.5×–3×), click-and-drag pan, hover-to-highlight the connected path (dims everything else to 0.15 opacity).

---

## 8. Diagram rendering algorithm

Custom SVG radial layout, no charting library:

- **Polar coordinate placement**, root object at centre, each traversal depth on its own concentric ring.
- **Cascade-priority ordering:** from depth 2 onward, each ring is built in two passes — cascade relationships claim a child first, before lookup/restricted relationships for the same child are even considered — regardless of which parent is processed first in iteration order. This was a specific bug fix: without it, a child reachable via both a lookup (to one parent) and a master-detail (to a different parent) could have its cascade relationship silently hidden by whichever parent happened to be processed first (e.g. `OpportunityContactRole` was drawn connected via Lookup to Contact instead of via Master-Detail to Opportunity, despite the text list correctly showing cascade). Depth 1 skips this (only one possible parent: the root).
- **Multi-shell ("molecule/atom") layout:** a single ring has finite circumference — a large imported org schema can put 100+ objects on one node's direct relationships, which no amount of label-collision cleverness fixes on a physically too-small ring. Items are split into concentric shells (max 18 per shell) via round-robin assignment on angle-sorted order, so angular neighbours land on *different* shells and maximise separation between labels that would otherwise be closest together.
- **Label collision resolution:** real text-width measurement via an offscreen canvas context (matching the actual loaded font, Inter) rather than a character-count heuristic — capital-heavy strings like `OpportunityContactRole` render far wider per character than short ones like `Task`, which a length-based proxy can't capture. Genuine bounding-box overlaps are resolved with a retry loop (up to 10 attempts): alternately push the label radius outward or nudge it vertically.
- **Per-parent angular budget:** the angular spread allotted to one parent's children is capped by that parent's actual available slot width — a fixed spread formula that ignores sibling count is what causes neighbouring parents' territories (and their connector lines) to visibly overlap and cross.
- Labels are always drawn *outside* their node circle (never inside) — API names are long single words with no natural wrap point, so cramming them inside a small circle clips them.

---

## 9. Exports

Both client-side `Blob` downloads, no server round-trip:
- **Data Dictionary (.csv)** — the full blast-radius list for the current object/depth.
- **Risk Brief (.md)** — root object, traversal depth, generation date, an impact-count summary table, itemised cascade/orphaned/restricted sections (object, API name, via-relationship, depth), and the same "does not account for custom Apex/Flows/Validation Rules" disclaimer as the on-page footer.

---

## 10. Non-functional requirements

- Single-file, dependency-free (no build step, no framework) — consistent with the rest of the lab, with the one deliberate, gracefully-degrading exception in §6.
- No login flow, no credentials collected or transmitted, ever — both import paths rely on the user's own already-authenticated session or their own exported logs.
- No data leaves the browser except the described optional live API-version ping (which sends nothing, only receives).
- SVG diagram is given `role="img"` and a descriptive `aria-label` for accessibility.
- British English spelling throughout.

---

## 11. Decisions log

Reconstructed from commit history, kept here so the reasoning isn't lost:

| Decision | Outcome | Rationale |
|---|---|---|
| Import format for bulk/org-wide data | **Line-based (`SCHEMA\|...`), not JSON** | Apex debug logs truncate at a size limit; a cut JSON payload is entirely unparseable, a cut line-list only loses its last line. |
| API version check domain | **`test.salesforce.com` (sandbox) only, never production** | Avoids any implication of touching a real org; accepted that this may simply not respond due to CORS, and built the fallback to match. |
| Official-reference-PDF batch relationship type | **Default to `lookup` uniformly, even where cascade behaviour is independently suspected** | The source document itself doesn't distinguish cascade from lookup — guessing would misrepresent confidence the tool doesn't actually have. |
| Cascade vs. lookup priority in both the impact list and the diagram | **Cascade always wins when a child is reachable both ways** | Matches real platform behaviour (a cascade delete happens regardless of what else also points at the same record) and fixes a specific diagram/list mismatch bug. |
| Diagram ring capacity | **Multi-shell layout, not a single ring** | A single ring has finite circumference; no label-collision algorithm fixes a ring that's physically too small for the object count. |
| Label collision detection | **Real canvas text measurement, not character-count** | Capital-heavy object names render far wider per character than short ones; a length proxy under/overestimates badly enough to still collide. |
| Object picker structure | **Category tabs + search over a flat list** | ~300 objects as one flat wall of buttons is unusable; tabs with live counts let users narrow to a domain first. |

---

## 12. Known gaps (open items, not yet fixed)

- **Bug:** 9 objects are defined with `category: 'Field Service'` (`WorkOrder`, `WorkOrderLineItem`, `ServiceAppointment`, `AssignedResource`, `ServiceResource`, `ServiceTerritory`, `ServiceContract`, `MaintenanceAsset`, `MaintenancePlan`), but the `CATEGORIES` array the picker iterates over does not include `'Field Service'` at all — these objects are fully modelled but permanently unreachable in the UI (not shown, not searchable, not counted). One-line fix: add `'Field Service'` to `CATEGORIES`.
- No automated tests exist for the impact algorithm or the import parser, unlike Recoverly's `test.js` against a worked example.
- No dark mode / `prefers-color-scheme` handling.
- Objects present in `OBJECTS` with no corresponding `RELATIONSHIPS` entries are silently absent from any result rather than flagged as "not modelled" the way Industry Cloud objects explicitly are — worth deciding whether that same low-confidence banner should extend more broadly.
