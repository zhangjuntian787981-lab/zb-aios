# Repository agent instructions

## Agent skills

### Issue tracker

Issue tracking uses the existing governed work-package workflow (`Other`): the Manifest defines work, the online D1 append-only ledger records work-package and Gate state, and Git freezes engineering evidence. Do not create `.scratch` or a parallel task/progress truth. See `docs/agents/issue-tracker.md`.

### Triage labels

The default triage vocabulary applies only to future Bugs or external requests. It never represents F/C/O/T work-package status. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. Read the existing root `CONTEXT.md` and relevant ADRs under `docs/adr/`; do not replace or duplicate them. See `docs/agents/domain.md`.
