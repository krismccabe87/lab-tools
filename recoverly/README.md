# Recoverly

A free data recovery maturity assessment. Answer 12 questions, get a Risk
Assessment and a tailored Data Recovery Response Plan.

**Full methodology and build spec:** see `REQUIREMENTS.md` in this folder —
the maturity model, all 12 assessment dimensions with their question
wording and level descriptions, industry weighting, scoring maths, and
architecture decisions all live there.

## Status: v1 built, with post-v1 enhancements

*This list is feature-level. For structural/content changes to the Response Plan itself (new sections, the accordion rewrite, etc.), see REQUIREMENTS.md §15's "Post-v1 additions" instead — the two lists don't overlap.*

- Assessment, Risk Assessment, and Response Plan tabs — working
- Radar chart, priority-gap ranking, industry-weighted scoring — working
- **Editable weights** — the industry preset is a starting point, not fixed; adjust any dimension's weight directly
- **Multi-assessment support** — opt-in, client-side only ("Remember my assessments on this device"): save, switch between, rename, and delete named assessments (e.g. one per system)
- **Calculator handoff** — the full RTO/RPO breakdown (realistic figures, gaps, individual costs, MTD status, data volume) passes through from the downtime calculator via URL params, shown as a structured table in the Response Plan and both exports — a genuine combined view, not just a headline number
- **Delete all saved data** — one button fully clears local storage, completing the "nothing leaves your browser" promise rather than requiring assessments to be deleted one at a time
- JSON save/load — working, fully client-side, no server storage. Loading a file while "Remember" is on now creates a new named assessment rather than silently overwriting whatever was active
- PDF export — working, plain reliable print (not paginated with a custom footer — see decisions log)
- Word export — working, includes the Recoverly logo and matches the app's brand colours/fonts
- **Automated tests** — `node test.js` verifies the scoring algorithm against the worked example in REQUIREMENTS.md §12

## Not yet built

- Backend email sending (the Email results button was removed entirely — its mailto-only output wasn't useful enough to keep)
- A real, paginated PDF with a custom branded footer (Paged.js was tried, produced a blank print in practice, was pulled — see REQUIREMENTS.md §15)
