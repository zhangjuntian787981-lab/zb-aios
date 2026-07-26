# C13 bounded context

## Purpose

C13 owns the lifecycle and Run-time resolution of versioned Skill releases. It does not own user identity, authorization policy, enterprise data, tool execution, model routing, or a code sandbox.

## Ubiquitous language

| Term | Exact meaning in C13 |
|---|---|
| Skill | A Tenant-scoped logical capability identified by `skillId`. |
| Skill Manifest | The closed seven-field, instructions-only JSON contract. |
| Skill Release | One immutable Manifest, semantic version, source-review evidence, and canonical SHA-256. |
| Release state version | CAS counter for governance transitions; it is not the semantic Skill version. |
| Static check | Deterministic validation that the Manifest is closed, instructions-only, script-free, and treats `allowedTools` as advisory. |
| Synthetic evaluation | The closed F04 report bound to the exact Tenant, Skill, semantic version, release digest, frozen suite, human decision, report artifact and per-case evidence. Missing case evidence produces `BLOCKED`. |
| Approval | An explicit transition that repeats the exact content hash, evaluation report reference/hash and human-decision reference/hash after a passing evaluation. |
| Channel | A mutable `PILOT` or `STABLE` pointer with its own CAS generation. |
| Publication history | Monotonic evidence that a release was previously published to a channel. |
| Withdrawal | An irreversible release state that clears every channel currently pointing at it. |
| Rollback | Moving one channel to an eligible release previously published to that same channel. |
| Run resolution | A C06 `READ`-protected lookup that binds a new Run to the current channel, semantic version, and immutable digest. |

## Invariants

1. Release Manifest, semantic version, source evidence, and content SHA-256 never change.
2. `SUBMITTED → STATIC_PASSED → EVALUATED → APPROVED` is the only successful approval path.
3. `STABLE` requires prior `PILOT` publication of the same release.
4. A failed evaluation cannot be approved.
5. A withdrawn release never becomes approved again and cannot resolve for a new Run.
6. Rollback targets must be approved, non-withdrawn, and previously published to the selected channel.
7. `allowedTools` describes intended operations only. C06 remains the sole runtime permission decision.
8. P1 exposes no script field and contains no script executor.
9. Every mutation is Tenant-scoped, idempotent, CAS-protected, and emits exactly one append-only event.
10. A stage approval does not validate the F04 human baseline; the
    separately bound governance reference records that decision, while
    all ten case results are still required for `PASS`.
11. Static, suite-binding and evaluation-report evidence becomes
    immutable when first written.
12. Submit, static check, evaluate, approve, publish, withdraw, rollback
    and resolve use distinct C06 resources and operation evidence.

## Outside this context

- C03 Tenant lifecycle and admission.
- C05 stable Principal and delegation resolution.
- C06 authorization decisions.
- C08 Case, Thread, Run, Artifact, and ToolCall state.
- C10 knowledge retrieval.
- C14 model routing.
- C16 tool authorization and execution.
- O03 OCI packaging, SBOM, signing, and provenance; these are P2.
- Real enterprise adapters and data; these begin at P3.
