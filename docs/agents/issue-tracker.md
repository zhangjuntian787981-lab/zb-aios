# Issue Tracker

## Tracker choice

- **Type:** Other
- **Workflow:** Governed work-package workflow
- **Separate persistent issue store:** None
- **Local Markdown issue directory:** Prohibited
- **GitHub/GitLab issue workflow:** Not configured

This repository intentionally does not maintain a second task tracker.

Do not create `.scratch/`, a parallel checklist database, duplicate F/C/O/T tickets, or another source of work-package progress.

## Sources of truth

| Concern | Authoritative source |
| --- | --- |
| Definition, scope, dependency and Gate membership of the 37 work packages | `implementation/governance/work-package-manifest.v1.json` |
| Current work-package implementation and verification state | Online D1 append-only governance ledger |
| GateSubmission and GateDecision | Online D1 append-only governance ledger |
| Source code, tests, frozen receipts and acceptance evidence | Git frozen evidence identified by commit, tree or content hash |
| Domain vocabulary | Root `CONTEXT.md` |
| Durable architecture decisions | `docs/adr/` |

The Manifest is the work-package definition baseline. It is not the live status projection.

Local seed or example governance files are not substitutes for the online D1 ledger.

Plans, specs, conversations, labels, checklists and triage notes are not authoritative work-package status.

## Work-package identity rules

The existing work packages are:

- F01–F04
- C01–C19
- O01–O06
- T01–T08

`to-spec`, `to-tickets` and `triage` must treat these identifiers as existing governed work packages.

They must not:

- mint another F/C/O/T identifier;
- renumber an existing work package;
- copy a work package into another tracker;
- represent a work package as a newly created Issue or Ticket;
- alter dependencies, Applicability or Gate membership;
- mark a work package started, implemented or verified outside the D1 governance workflow;
- bypass `allowedToStart`, dependency or Stage Gate rules.

Changing the 37-item definition baseline requires a separate, explicit governance change. These skills must stop and request Product Owner direction instead of editing the Manifest automatically.

## Workflow for existing work packages

Before proposing or performing work:

1. Read `CONTEXT.md` and the relevant ADRs.
2. Resolve the existing work-package ID from the Manifest.
3. Read the current state from the authorized online D1 projection.
4. Read the relevant Git-frozen evidence.
5. Confirm that dependencies and the current Product Phase permit the work.
6. Keep implementation, verification and Stage Approval separate.
7. Store source, tests and frozen acceptance evidence in Git.
8. Record work-package state and Gate events only through the authorized append-only D1 governance interface.

A Git commit, spec, label, checklist or passing test does not by itself change work-package status.

A D1 status event does not replace the corresponding Git evidence.

## Future Bugs and external requests

Triage applies only to a genuinely new Bug or external request. It does not triage the existing 37 work packages.

Because no separate persistent intake tracker is currently configured, triage is draft-only:

1. Examine the supplied request and the existing Product Core.
2. Check whether the behavior already belongs to an existing F/C/O/T work package.
3. Recommend one of:
   - route the request into an existing work package;
   - request more information;
   - propose an explicit Manifest governance change;
   - hold or reject the request.
4. Present the recommendation and proposed triage label to the Product Owner.
5. Do not create a persistent Issue, Ticket, label, comment, closure or status record automatically.

If the Product Owner routes the request into an existing work package, the D1 ledger remains the only source of that work package’s state.

If the request would change the 37-item baseline, stop before creating an identifier or editing the Manifest.

If a persistent external intake system is configured later, update this file before `triage`, `to-spec` or `to-tickets` writes to it.

## Skill-specific rules

### `to-spec`

`to-spec` may synthesize a specification in the conversation.

It must:

- use the vocabulary in `CONTEXT.md`;
- respect relevant ADRs;
- identify the existing work package or state that the request is not yet governed;
- prefer existing test seams;
- keep the specification non-authoritative for work-package status.

It must not:

- create a new F/C/O/T work package;
- publish into `.scratch`;
- write a D1 event;
- treat the spec as implementation, verification or Stage Approval.

If the Product Owner later authorizes an exact Git path for the specification, it may be saved as a non-status artifact. That separate authorization must identify the path and preserve the existing governance sources.

### `to-tickets`

`to-tickets` may propose tracer-bullet implementation slices in the conversation.

Those slices are planning aids inside an existing governed work package. They are not new project work packages and do not have authoritative progress state.

It must not:

- publish one persistent Issue per slice;
- create `.scratch/<feature>/issues/`;
- assign F/C/O/T identifiers;
- maintain checkbox progress separate from D1;
- alter work-package dependencies or Applicability;
- start a blocked work package.

Any durable implementation breakdown requires a separately approved exact path and must clearly state that D1 remains the only source of work-package status.

### `triage`

`triage` may classify future Bugs or external requests using the vocabulary in `docs/agents/triage-labels.md`.

It must not:

- apply triage labels to F/C/O/T work packages;
- interpret a triage label as `NOT_STARTED`, `IN_PROGRESS`, `IMPLEMENTED` or `VERIFIED`;
- change D1 work-package or Gate state;
- create a second progress queue;
- automatically create `.scratch` or another intake directory.

Until a persistent intake surface is explicitly configured, label changes, comments, closures and out-of-scope records remain recommendations shown to the Product Owner before any write.

## D1 governance boundary

Only the authorized governance path may append:

- work-package implementation events;
- work-package verification events;
- GateSubmission;
- GateDecision;
- Applicability decisions when supported by the governed schema;
- `P2_ACCEPTANCE_PROFILE_APPROVED`;
- `P2_WORK_PACKAGE_START_AUTHORIZED`.

Both P2 event types must be appended to the same online D1 append-only
governance ledger. They do not create a second task, progress or status source.

A `P2_ACCEPTANCE_PROFILE_APPROVED` event must bind the exact Profile SHA-256,
Receipt Schema SHA-256, Validator SHA-256, a verified real source commit and
the `executionBaselineDigest` reproduced from that commit.

An O02 or O03 `P2_WORK_PACKAGE_START_AUTHORIZED` event must reference a valid
`P2_ACCEPTANCE_PROFILE_APPROVED` event at a lower D1 revision. A superseding
Profile, an authorization revocation, a duplicate event or authorization ID, a
revision gap, or invalid causal order must fail closed.

Do not edit a local JSON seed and present it as current D1 state.

Do not use a Git commit, Issue label, PR status, spec approval or chat confirmation to imitate a D1 governance event.

A Git Candidate file, chat confirmation, passing test or ordinary commit cannot
substitute for either P2 D1 event.

## Git evidence boundary

Git frozen evidence is authoritative for:

- exact source;
- exact test implementation;
- test output and receipts;
- acceptance artifacts;
- commit, tree and content hashes.

Working-tree changes are not frozen evidence until the required verification and freeze process completes.

Git evidence must not be interpreted as Product Owner Stage Approval unless the corresponding immutable GateDecision exists in D1.

## Prohibited parallel truth

The following are prohibited unless this workflow is explicitly reconfigured:

- `.scratch/`;
- a second work-package list;
- duplicate F/C/O/T Issues;
- spreadsheet or Markdown work-package status;
- triage labels used as phase progress;
- a local governance event file treated as the live ledger;
- automatic migration to GitHub, GitLab, Jira, Linear or another tracker.

To change issue-tracker strategy, edit this file through an explicit, reviewed setup change.
