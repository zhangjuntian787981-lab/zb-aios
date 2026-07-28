# Triage Labels

These labels apply only to future Bugs or external requests.

They are not work-package states, Product Phases, Applicability values, Gate states or evidence results.

## Default mapping

| Label in mattpocock/skills | Label in this workflow | Meaning |
| --- | --- | --- |
| `needs-triage` | `needs-triage` | Product Owner or maintainer still needs to evaluate the request |
| `needs-info` | `needs-info` | The request cannot be evaluated until the reporter supplies specific missing information |
| `ready-for-agent` | `ready-for-agent` | The request is sufficiently specified for an Agent to work on after governance routing |
| `ready-for-human` | `ready-for-human` | The request requires human judgment, access, authority or implementation |
| `wontfix` | `wontfix` | The request will not be actioned |

## Scope rules

- Do not apply these labels to F01–F04, C01–C19, O01–O06 or T01–T08.
- `ready-for-agent` does not mean an existing work package is allowed to start.
- `ready-for-human` does not grant Runtime Authorization or HumanDecision authority.
- `wontfix` does not change Work Package Applicability.
- A triage label never changes D1 implementation status, verification status, GateSubmission or GateDecision.
- The `bug` and `enhancement` categories describe the type of a future request; they do not represent work-package status.

## Current write behavior

No persistent external request tracker is currently configured.

Until one is configured, these values are recommendation metadata shown in triage output. They are not written to D1, Git, `.scratch` or another queue.

If an external request tracker is adopted later, update the right-hand mapping in this file before applying labels there.
