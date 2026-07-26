# C13 Skill Registry

## Outcome

C13 implements a P1, Synthetic-only Skill Release registry with immutable content hashes and an explicit governance path:

```text
SUBMITTED
  → STATIC_PASSED
  → EVALUATED
  → APPROVED
  → PILOT
  → STABLE
```

A release can then be withdrawn, or a channel can be rolled back to a previously published eligible release. A new Run receives a Skill only when the requested semantic version and SHA-256 exactly match the approved, non-withdrawn release currently selected by the requested channel.

The checked-in F04 human baseline is still
`PENDING_HUMAN_VALIDATION`. Therefore the real frozen C13 Synthetic
catalog returns `BLOCKED`, and no checked-in release can be approved or
published. Lifecycle success tests inject an explicitly named test-only
validated report so that the state machine and PostgreSQL recovery can be
tested without misrepresenting the pending Product Owner decision.

## Public module seams

- `validateSkillManifest` checks the closed P1 Manifest.
- `canonicalSkillManifestSha256` hashes deterministic canonical JSON for this closed JSON subset.
- `createSkillRegistry` exposes `execute` and `resolveForRun`.
- `createMemorySkillRegistryStore` supports deterministic unit and concurrency tests.
- `createPostgresSkillRegistryStore` uses signed C07 transaction scope, SERIALIZABLE commands, idempotent receipts, CAS, FORCE RLS, and recovery after an uncertain commit acknowledgement.
- `createC13C06Authorizer` adapts the real C06 Authorization Facade.
- `createC13SyntheticSkillCatalog` binds the three F02 Tenants to source-review and F04 evaluation evidence.
- `synthetic-evaluation-reports.v1.json` contains the reproducible blocked
  F04 gate results bound to the real pending baseline and exact release
  digests.

The OpenAPI contract is `skill-registry.openapi.v1.json`; the closed Manifest schema is `skill-manifest.v1.schema.json`.

## Manifest

The only P1 fields are:

```json
{
  "schemaVersion": "1.0.0",
  "name": "analyze-synthetic-order",
  "version": "1.0.0",
  "description": "Analyze a fictitious order with cited synthetic evidence.",
  "instructions": "Use only the supplied Synthetic evidence. Return a concise finding and cite each source.",
  "allowedTools": ["catalog.read"],
  "executionMode": "INSTRUCTIONS_ONLY"
}
```

There is no script field. `executionMode` has one value. `allowedTools` is advisory metadata and never grants runtime permission; C06/C16 must authorize the actual operation again.

## Persistence and concurrency

Migration order is fixed:

1. `0019_skill_registry.sql`
2. `0020_skill_registry_runtime_roles.sql`

The four C13 tables are:

- `skill_release`: immutable content plus CAS-governed lifecycle state.
- `skill_channel`: `PILOT`/`STABLE` pointer with an independent generation.
- `skill_event`: append-only evidence.
- `command_receipt`: append-only idempotency recovery record.

`aios_c13_runtime` is `NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS`, cannot delete, cannot update events or receipts, and cannot issue C07 scope signatures. The Store rejects a login that combines C13 runtime and C07 scope-signing roles.

## Run resolution rules

Resolution fails closed when:

- the F04 human baseline remains pending or its report hash differs;
- no release is published on the channel;
- static check or evaluation has not passed;
- explicit approval is absent;
- the semantic version or digest differs;
- the release is withdrawn;
- Tenant, C05 identity, C06 authorization, or C07 scope binding differs.

Existing Runs should persist the returned `releaseId`, semantic version, and `contentSha256` in their C08 Run Manifest. Withdrawal blocks new resolution; it does not rewrite historical Run evidence.

## Verification

Run only the C13 suite:

```sh
sh scripts/run-c13-tests.sh
```

The PostgreSQL scripts create isolated local PostgreSQL 17 clusters under guarded `/tmp/c13-*.XXXXXX` paths, require pgvector because C07 does, and delete only those temporary clusters after a clean shutdown.

`tests/c13-synthetic-skill-catalog.test.mjs` recomputes the F04 gate
outcome from the frozen suite, gate configuration and pending human
baseline. It must remain `BLOCKED`. The PostgreSQL lifecycle test uses a
test-only validated report fixture; it is evidence for state transitions,
not evidence that the pending F04 human baseline was approved.

## Deliberate boundaries

- All data and references are Synthetic. Enterprise sources and adapters remain disabled until P3.
- C13 does not execute Skills, tools, Python, shell, JavaScript, or arbitrary code.
- No Product Owner or human baseline approval is inferred from G0. Until
  a separate immutable human validation exists, the checked-in catalog
  cannot reach `EVALUATED`, `APPROVED`, `PILOT` or `STABLE`.
- Git PR/CODEOWNERS is represented in P1 by the frozen `sourceReviewRef` plus SHA-256; connecting a real repository is outside this Synthetic package.
- OCI packaging, SBOM, artifact signing, signature verification, and provenance are O03 work in P2. Their absence is not disguised as a P1 capability.
- This package does not modify the governance Manifest, progress dashboard, or any other work package.
