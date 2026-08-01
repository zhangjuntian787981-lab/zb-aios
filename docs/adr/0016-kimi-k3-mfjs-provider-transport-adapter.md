# ADR 0016: Kimi K3 MFJS provider transport adapter

- Status: Candidate
- Date: 2026-08-01
- Supersedes for future K3 calls: the response-schema transport portion of ADR 0013 and ADR 0015
- Historical effect: none

## Context

The first formal Kimi K3 review reached the provider once and returned HTTP 400. The provider rejected the submitted response schema because an enum field under `$defs` did not declare an explicit `type`. The failed review remains `INCONCLUSIVE`; this decision does not alter or reinterpret its request, response, diagnostic evidence, or governance effect.

The repository's canonical `independent-model-review-output.v2` Schema contains the provider-independent governance contract. Moonshot Structured Output accepts a more limited JSON Schema dialect (MFJS). Sending the canonical Schema unchanged therefore makes the provider transport contract incompatible without making the canonical governance contract invalid.

## Decision

Add an append-only Moonshot MFJS transport Schema and keep the canonical v2 Schema byte-for-byte unchanged.

For a future K3 call:

1. the formal request embeds only the frozen MFJS provider transport Schema;
2. the exact raw UTF-8 model `content` must validate against that provider Schema;
3. the same unmodified bytes must then validate against the canonical v2 Schema and its existing semantic validator;
4. Transport Evidence v4 binds both exact Schema paths and byte SHA-256 values;
5. Receipt v6 binds Transport Evidence v4 and both Schema byte SHA-256 values.
6. a failed future call uses append-only Chat Diagnostic Evidence v2, which binds both exact Schema paths and both byte SHA-256 values before preserving any safe response artifact.

No conversion, default insertion, field removal, or rewritten model output is permitted between the two validations. Either validation failing is fail-closed and cannot produce a Review Receipt.

## Compatibility and history

Transport Evidence v3, Receipt v5, Chat Diagnostic Evidence v1, ADR 0013, ADR 0015, and all prior K3 evidence remain unchanged and retain their original meaning. Runtime version selection is based on files present in the exact source commit so historical v3/v5/v1 evidence remains replayable. The provider adapter is not a model fallback, a retry authorization, or a governance approval.

## Consequences

- Provider-specific syntax is isolated from the provider-independent output contract.
- A future successful Receipt proves both provider transport compatibility and canonical governance validity for the same bytes.
- The prior HTTP 400 remains a failed attempt and cannot be promoted to `MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION`.
- This ADR causes no D1, Gate, Profile, work-package, deployment, or remote state change.
