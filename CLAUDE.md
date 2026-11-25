# Claude Code Instructions — lab-tools

## Project Context
- **Public repository** — this is the public snapshot of the `lab.krismccabe.com` static tools. Never commit secrets, tokens, private URLs, or internal operational details to `HANDOFF.md`, `CLAUDE.md`, or git history.
- Tools with a `src/` directory (`ai-shield/`, `flare/`) are compiled into `index.html` by `python3 build.py` inside `src/`.
- `.assetsignore` excludes `CLAUDE.md` and `HANDOFF.md` from Cloudflare's deployed asset bundle so they stay in git without being served over HTTP.
- Always check `HANDOFF.md` on the active branch (and open PRs/branches) at the start of a session before making changes.

## Cross-Tool Handoff Protocol (Claude Code ↔ Antigravity)
Work in this repo may transition mid-task between **Claude Code** and **Antigravity** (for example, when hitting a session or usage limit). GitHub is the shared source of truth between both tools.

### Working & Checkpointing Rules
1. **Work on a feature branch** — avoid leaving substantial work uncommitted locally.
2. **Commit and push frequently** (`git push -u origin <branch>`) after each logical milestone or passing check so nothing is stranded in one session.
3. **Keep `HANDOFF.md` current** on your active branch:
   - Update `HANDOFF.md` **immediately** whenever the user says **"handoff"**, **"checkpoint"**, **"save state"**, or mentions approaching a limit.
   - Update `HANDOFF.md` after major milestones or before ending a session with unfinished work.
   - When a task/PR is finished, set `Status` to `Ready for Review` or `Idle` so the next session knows nothing is left mid-flight.
4. **Public-repo safety** — never record secrets, credentials, personal data, or private infrastructure details anywhere in this repository.

### Required `HANDOFF.md` Format
Keep `HANDOFF.md` concise and actionable using these sections:
- **Last updated**: UTC timestamp + tool (`Claude Code` or `Antigravity`)
- **Branch / PR**: active branch name and PR link (if open)
- **Status**: `In Progress` | `Blocked` | `Ready for Review` | `Idle`
- **Goal**: 1–2 sentences on what is being built or fixed
- **Completed**: bulleted list of finished items (with key files or commit SHAs)
- **Next steps**: ordered, concrete actions so another agent can resume cold
- **Verification & gotchas**: commands/tests run, build notes, or pitfalls discovered
- **Open questions**: decisions or clarifications waiting on the user
