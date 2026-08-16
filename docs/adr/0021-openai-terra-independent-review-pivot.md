# ADR 0021: OpenAI Terra independent-review transport candidate

- Status: Candidate
- Date: 2026-08-05
- Scope: P0-P2 synthetic-data independent model review only

## Context

The Kimi K3 transport line produced useful failure evidence but no compliant review Receipt. Its commits, ADRs, requests, responses, diagnostics, and outcomes remain immutable history. They are not current review evidence and must not recursively enter model-visible review material.

The provider-neutral Policy v2, output contract, byte binding, Git binding, repository snapshot, and preproduction-only conclusion remain authoritative. A new transport candidate is needed for a distinct reviewer model without changing D1, Gate, Profile, work-package, or P3 human-review semantics.

## Decision

Use `openai/gpt-5.6-sol` as the implementation identity and request `openai/gpt-5.6-terra` with `reasoningEffort=high` as the distinct reviewer identity. The candidate:

1. reviews the exact current bytes of the frozen 22-path provider-neutral core plus the Terra adapter, config, schemas, ADR, test, repository instructions, and authorization prompt;
2. claims only `CORE_SUBJECT_ONLY_NOT_FULL_REPOSITORY_CLEARANCE`;
3. caps model-visible bytes at 768 KiB and omits K3 history from the current Subject; any future K3 reference must be closed metadata containing commit, tree, path, mode, byte length, SHA-256, historical `BLOCKED`/`INCONCLUSIVE`, and `governanceEffect=NONE` only;
4. requires a fresh ephemeral session with user config, project rules, implementation conversation, and implementation conclusions absent;
5. permits one formal attempt only after either `API_NO_TOOLS` or `OS_ENFORCED_TARGET_READ_ONLY` is proved;
6. binds the Codex CLI path, version, exact bytes, requested and actual model, session, JSONL, stderr, final message, schemas, source commit/tree, and repository snapshots;
7. issues a v10 Receipt only from validated trusted runtime evidence.

The currently inspected Codex CLI has no option that proves an empty tool set. The existing macOS isolation probe does not prove that a real Terra invocation can both reach the model service and be restricted to the Review Subject. Therefore the formal launcher remains fail closed with `OPENAI_TERRA_ISOLATION_NOT_PROVED`; this ADR does not authorize a Terra call by itself.

## Consequences

- Kimi history remains byte-identical and has no current review effect.
- Caller-authored booleans or legacy runtime attestations cannot enable a formal call or Receipt.
- Only a compliant `CLEAR` v10 Receipt may state `MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION`.
- `BLOCKED`, `INCONCLUSIVE`, transport failure, missing isolation proof, or scope failure are not success.
- Model review is never represented as human review. P3 and the listed high-risk scopes still require a real second human reviewer.
- No D1 event, Gate decision, Profile approval, work-package authorization, deployment, Ruleset, PR, or remote change follows from this candidate.
