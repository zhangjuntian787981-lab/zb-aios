# Keep P2 profile approval and start authorization in one D1 ledger

`P2_ACCEPTANCE_PROFILE_APPROVED` and `P2_WORK_PACKAGE_START_AUTHORIZED` are distinct events appended to the existing online D1 append-only governance ledger. They do not establish a second state store, task tracker or progress truth. A Profile Approval binds the governed Profile and its Git-frozen engineering evidence; a Work Package Start Authorization separately decides whether one named work package may start under that approved Profile.

O02 and O03 require separate `P2_WORK_PACKAGE_START_AUTHORIZED` events. Each authorization must reference a valid `P2_ACCEPTANCE_PROFILE_APPROVED` event at a lower D1 revision, and O03 remains subject to its Manifest dependency on O02. When a Profile Approval is superseded, every start authorization bound to the older Profile becomes stale immediately and fails closed.

Git-frozen evidence proves exact source code, tests and acceptance material but creates no governance effect by itself. The v2 Candidate becomes effective only after a real `P2_ACCEPTANCE_PROFILE_APPROVED` event is appended through the authorized D1 path. This ADR does not modify the Manifest, any GateSubmission or GateDecision, work-package state, or P0/P1 history.
