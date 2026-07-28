# Domain Docs

This repository uses a single domain context.

The engineering skills must consume the existing domain documentation rather than creating a replacement hierarchy.

## Existing layout

```text
/
├── CONTEXT.md
└── docs/
    └── adr/
        ├── 0001-generic-product-before-enterprise-onboarding.md
        ├── 0002-work-packages-not-microservices.md
        └── 0003-hash-bound-stage-gate-submissions.md
```

There is no `CONTEXT-MAP.md` and no context-specific `src/*/docs/adr/` layout.

Do not create either unless the repository genuinely becomes a multi-context monorepo and the Product Owner explicitly approves the migration.

## Before exploring or changing the codebase

1. Read the root `CONTEXT.md`.
2. Use its defined domain terms in specs, tickets, triage notes, code, tests and reviews.
3. Read every ADR relevant to the area being changed.
4. Check whether the proposed work conflicts with an existing ADR.
5. Read the current work-package definition from `implementation/governance/work-package-manifest.v1.json`.
6. Read current work-package and Gate state from the authorized online D1 projection.
7. Read relevant Git-frozen evidence before claiming that behavior is implemented or verified.

If a domain document is absent, proceed without creating one automatically.

## Preserve existing documents

Do not overwrite, replace, regenerate or truncate the existing root `CONTEXT.md` or any existing ADR.

A task may update domain documentation only when:

- the user explicitly asks for a domain change; or
- a durable domain decision is made during an authorized domain-modeling workflow.

Such an update must be surgical, preserve unrelated content and identify any changed terminology or superseded decision.

New ADRs must be additive. Do not silently rewrite an earlier ADR to make a new implementation appear compliant.

## Use the glossary’s vocabulary

Use the terms defined in `CONTEXT.md`, including:

- Product Owner;
- Target Enterprise;
- Tenant and Synthetic Tenant;
- Enterprise User and Tenant Principal;
- Product Core;
- Product Phase and Stage Gate;
- Project Work Package;
- Gate Submission and Gate Decision;
- Runtime Authorization;
- HumanDecision;
- Connector Template, Connector Instance and Connector Stage.

Do not replace these terms with avoided synonyms that change authority or scope.

If a required concept is missing, first consider whether the proposed work is inventing unnecessary language. If the gap is real, surface it for an explicit domain-modeling decision.

## Flag ADR conflicts

If a proposal conflicts with an existing ADR, state the conflict before implementation.

Use this form:

> Contradicts ADR-XXXX (`<title>`) because `<reason>`. This requires an explicit decision to retain, amend or supersede the ADR before implementation.

Do not silently override an ADR through code, a spec, a Ticket or a triage decision.

## Authority boundary

Domain documentation explains vocabulary and durable design decisions. It is not a work tracker or acceptance ledger.

It must not replace:

- `implementation/governance/work-package-manifest.v1.json` for the 37 work-package definitions;
- the online D1 append-only governance ledger for work-package status, GateSubmission or GateDecision;
- Git frozen evidence for source, tests and acceptance results.

A change to `CONTEXT.md` or an ADR does not itself change work-package status, Product Phase, Applicability, Runtime Authorization or HumanDecision.
