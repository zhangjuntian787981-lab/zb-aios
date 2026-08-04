# ADR 0020: Kimi K3 segmented independent review candidate

- Status: Candidate, local only
- Date: 2026-08-04
- Historical single-call evidence effect: none
- Network execution authorization: none
- Future contract supersession: ADR 0019's prohibition on segmented review is
  superseded only for post-V7 review candidates

## Context

The final authorized monolithic Kimi K3 attempt did not produce a compliant
Receipt. Its exact failure evidence remains historical and does not establish
review clearance. The complete fixed-base review scope must remain intact, but
future review can separate independent reading responsibility from deterministic
aggregation without replacing original Git bytes with summaries.

This candidate explicitly supersedes, for future post-V7 review candidates
only, ADR 0019's prohibition on segmented review. It does not alter, reinterpret,
or authorize a retry of any historical V7 attempt or evidence.

## Decision

The local candidate has three distinct layers:

1. Four independent content reviews own disjoint path sets:
   `GOVERNANCE_LINEAGE`, `SCHEMAS_WIRE_CONTRACTS`,
   `RUNTIME_ORCHESTRATION`, and `TESTS_VERIFICATION`. Their union is exactly
   the Review Bundle `reviewedPaths`. Every owned path enters its Segment
   Material as the complete frozen Git blob.
2. A fifth `CROSS_CUTTING_INTEGRATION` model review reads the four validated
   Segment Receipts, complete Git patch, Bundle path inventory, and fixed
   cross-module contracts. Dependencies are reviewed from the complete patch
   and frozen contracts; the Bundle is not misrepresented as a dependency
   graph. Repeated reading does not alter content ownership.
3. A local pure function binds the exact SHA-256 of four Segment Receipts and
   one Integration Receipt. It makes no model or network call, carries no model
   session or transport evidence, and does not add, remove, resolve, or rewrite
   findings.

The model never authors a Receipt. It returns only the closed segmented-review
output. A trusted local verifier re-reads the exact Segment or Integration
Material, Token Estimate Evidence, transport evidence, formal request, raw
response, parsed content, and before/after repository snapshots. Only a private
proof produced by that complete verification can construct a Receipt. Decision,
findings, reviewer session, usage, cost, timestamps, and artifact bindings are
derived from the verified bytes; caller-supplied outcome fields or bare digests
cannot substitute for them. The four Segment sessions must be distinct and the
Integration session must be a fifth distinct session.

Every content path is model-visible in exactly one content segment. A binding
whose Git path is also in the cumulative `reviewedPaths` is carried as raw bytes
only by its owning segment; other segments retain the frozen descriptor binding
without duplicating those bytes. The Integration review deliberately re-reads
the complete patch and the fixed Policy/ADR/cross-module contract set; that
cross-cutting reread does not change content ownership.

The deterministic priority is fail closed: a missing, invalid, or
`INCONCLUSIVE` input means `INCONCLUSIVE`; otherwise any `BLOCKED` input means
`BLOCKED`; only five valid `CLEAR` inputs produce
`MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION`.

Five historical derived artifacts named by the Segment Plan remain complete
raw Git bytes in the governance segment. No summary or historical reference
substitutes for those bytes. Plan and material construction use committed Git
objects, so dirty worktree bytes cannot enter a frozen candidate.

The verifier operates under the existing local-control-plane assurance boundary
from Policy v2 and ADR 0011. It proves closed-field byte, source, transport,
repository-snapshot, Schema, semantic, session, and cost consistency; it does
not provide external non-repudiation against the local host owner. Synthetic
test fixtures and caller-assembled evidence are not governance evidence. This
candidate adds no runtime launcher or Receipt publication authority; any future
network execution and evidence freeze require a separately approved trusted
composition root and exact Git evidence commit.

## Budget boundary

This candidate records five expected Token Estimate requests and up to five
conditional Chat requests. It grants no network or spending authorization.
Exact segment material byte counts, future official Token Estimates, and a
separately approved budget are prerequisites for any external execution. No
fixed aggregate USD amount in this ADR authorizes a run.

## Consequences

- Segment and integration Receipts cannot claim global clearance.
- A Receipt cannot be constructed from caller-authored outcome fields or a
  self-reported material digest.
- Verified Plan and Receipt sets use immutable canonical snapshots; later
  caller mutation and duplicate Finding IDs fail closed.
- The aggregate cannot claim human review or cause D1, Gate, Profile, work
  package, deployment, GitHub, or Ruleset effects.
- Previous monolithic attempts, diagnostics, and ADRs remain byte-identical and
  retain their original non-clear conclusions.
- This local candidate does not invoke Kimi, Keychain, network, or governance
  write paths.
