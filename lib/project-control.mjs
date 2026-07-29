import { evaluateP2StartAuthorization } from "./p2-start-authorization.mjs";

const PHASES = ["P0", "P1", "P2", "P3"];
const GATES = ["G0", "G1", "G2", "G3"];
const IMPLEMENTATION_STATUSES = [
  "NOT_STARTED",
  "IN_PROGRESS",
  "IMPLEMENTED",
];
const VERIFICATION_STATUSES = ["NOT_VERIFIED", "VERIFIED"];
const DECISIONS = ["APPROVE", "APPROVE_WITH_EXCLUSIONS", "RETURN", "HOLD"];
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;

class ProjectControlError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ProjectControlError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new ProjectControlError(code, message);
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("INVALID_VALUE", "Non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("INVALID_VALUE", "Only JSON values can be canonicalized.");
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(
    typeof value === "string" ? value : canonicalize(value),
  );
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}

export {
  canonicalize as canonicalizeProjectJson,
  sha256 as sha256ProjectValue,
};

function assertStringArray(value, field) {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || !item.trim())
  ) {
    fail("INVALID_MANIFEST", `${field} must be an array of non-empty strings.`);
  }
}

function assertExactCommandKeys(command, expected) {
  if (
    canonicalize(Object.keys(command).sort()) !==
    canonicalize([...expected].sort())
  ) {
    fail("INVALID_COMMAND", "Command contains missing or unknown fields.");
  }
}

function assertNoUnknownCommandKeys(command, allowed) {
  if (
    Object.keys(command).some((key) => !allowed.includes(key))
  ) {
    fail("INVALID_COMMAND", "Command contains unknown fields.");
  }
}

function governedId(prefix, value) {
  const safe = String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!safe) fail("INVALID_COMMAND", "Could not generate a governance id.");
  return `${prefix}_${safe}`.slice(0, 132);
}

async function denyP2ExecutionBaseline(binding) {
  void binding;
  return false;
}

async function denyP2Readiness(binding) {
  void binding;
  return false;
}

async function denyReferenceReviewReadiness(binding) {
  void binding;
  return false;
}

async function readinessProved(verifier, binding) {
  try {
    return (await verifier(binding)) === true;
  } catch {
    return false;
  }
}

function compileManifest(manifest) {
  if (!manifest || typeof manifest !== "object") {
    fail("INVALID_MANIFEST", "Manifest must be a JSON object.");
  }
  const packages = manifest.work_packages;
  const gates = manifest.gates;
  if (!Array.isArray(packages) || packages.length !== 37) {
    fail("INVALID_MANIFEST", "Manifest must contain exactly 37 work packages.");
  }
  if (!Array.isArray(gates) || gates.length !== 4) {
    fail("INVALID_MANIFEST", "Manifest must contain exactly four gates.");
  }

  const packageById = new Map();
  const expectedEntryGate = { P0: null, P1: "G0", P2: "G1", P3: "G2" };
  for (const item of packages) {
    if (!/^(F|C|O|T)\d{2}$/.test(item.id) || packageById.has(item.id)) {
      fail("INVALID_MANIFEST", `Invalid or duplicate work package: ${item.id}`);
    }
    if (!PHASES.includes(item.phase)) {
      fail("INVALID_MANIFEST", `Invalid phase for ${item.id}.`);
    }
    if (item.phase_entry_gate !== expectedEntryGate[item.phase]) {
      fail("INVALID_MANIFEST", `Invalid phase entry gate for ${item.id}.`);
    }
    assertStringArray(item.acceptance_assertions, `${item.id}.acceptance_assertions`);
    assertStringArray(item.depends_on ?? [], `${item.id}.depends_on`);
    assertStringArray(item.artifact_refs ?? [], `${item.id}.artifact_refs`);
    assertStringArray(item.evidence_hashes ?? [], `${item.id}.evidence_hashes`);
    if (!IMPLEMENTATION_STATUSES.includes(item.implementation_status)) {
      fail("INVALID_MANIFEST", `Invalid implementation status for ${item.id}.`);
    }
    if (!VERIFICATION_STATUSES.includes(item.verification_status)) {
      fail("INVALID_MANIFEST", `Invalid verification status for ${item.id}.`);
    }
    const expectedStatus =
      item.verification_status === "VERIFIED"
        ? "VERIFIED"
        : item.implementation_status;
    if (item.status !== expectedStatus) {
      fail("INVALID_MANIFEST", `Derived status does not match ${item.id}.`);
    }
    if (
      item.verification_status === "VERIFIED" &&
      (item.implementation_status !== "IMPLEMENTED" ||
        item.artifact_refs.length === 0 ||
        item.evidence_hashes.length === 0 ||
        item.evidence_hashes.some((hash) => !SHA256.test(hash)) ||
        typeof item.verified_at !== "string" ||
        !item.verified_at)
    ) {
      fail(
        "INVALID_MANIFEST",
        `Verified package ${item.id} requires hashed evidence.`,
      );
    }
    packageById.set(item.id, item);
  }

  const expectedCounts = { P0: 4, P1: 19, P2: 6, P3: 8 };
  for (const phase of PHASES) {
    const count = packages.filter((item) => item.phase === phase).length;
    if (count !== expectedCounts[phase]) {
      fail("INVALID_MANIFEST", `${phase} must contain ${expectedCounts[phase]} packages.`);
    }
  }

  for (const item of packages) {
    for (const dependency of item.depends_on ?? []) {
      if (!packageById.has(dependency)) {
        fail("INVALID_MANIFEST", `${item.id} has unknown dependency ${dependency}.`);
      }
    }
    for (const group of item.depends_on_any_of ?? []) {
      assertStringArray(group, `${item.id}.depends_on_any_of`);
      for (const dependency of group) {
        if (!packageById.has(dependency)) {
          fail("INVALID_MANIFEST", `${item.id} has unknown dependency ${dependency}.`);
        }
      }
    }
  }

  const gateById = new Map();
  for (const gate of gates) {
    if (!GATES.includes(gate.id) || gateById.has(gate.id)) {
      fail("INVALID_MANIFEST", `Invalid or duplicate gate: ${gate.id}`);
    }
    if (!PHASES.includes(gate.phase)) {
      fail("INVALID_MANIFEST", `Invalid phase for gate ${gate.id}.`);
    }
    assertStringArray(gate.required_work_packages, `${gate.id}.required_work_packages`);
    if (
      gate.required_work_packages.some(
        (id) => packageById.get(id)?.phase !== gate.phase,
      )
    ) {
      fail("INVALID_MANIFEST", `${gate.id} contains a package from another phase.`);
    }
    const expectedRequired = packages
      .filter(
        (item) =>
          item.phase === gate.phase && item.applicability === "REQUIRED",
      )
      .map(({ id }) => id)
      .sort();
    const actualRequired = [...gate.required_work_packages].sort();
    if (canonicalize(actualRequired) !== canonicalize(expectedRequired)) {
      fail(
        "INVALID_MANIFEST",
        `${gate.id} must include every required work package in ${gate.phase}.`,
      );
    }
    gateById.set(gate.id, gate);
  }
  if (GATES.some((gateId) => !gateById.has(gateId))) {
    fail("INVALID_MANIFEST", "G0 through G3 are all required.");
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visiting.has(id)) fail("INVALID_MANIFEST", `Dependency cycle at ${id}.`);
    if (visited.has(id)) return;
    visiting.add(id);
    const item = packageById.get(id);
    const edges = [
      ...(item.depends_on ?? []),
      ...(item.depends_on_any_of ?? []).flat(),
    ];
    edges.forEach(visit);
    visiting.delete(id);
    visited.add(id);
  }
  packages.forEach(({ id }) => visit(id));

  return { manifest, packages, packageById, gates, gateById };
}

function hasRole(context, role) {
  return Array.isArray(context?.roles) && context.roles.includes(role);
}

function commandOutput(event) {
  if (event.type === "GATE_SUBMITTED") {
    return { submission: event.payload };
  }
  if (event.type === "GATE_DECIDED") {
    return { decision: event.payload };
  }
  if (event.type === "P2_ACCEPTANCE_PROFILE_APPROVED") {
    return { profileApproval: event.payload };
  }
  if (event.type === "P2_WORK_PACKAGE_START_AUTHORIZED") {
    return { startAuthorization: event.payload };
  }
  return {};
}

function projectState(
  compiled,
  journalState,
  evidenceValidationIssues = [],
  p2StartPolicy = null,
) {
  const packageState = new Map(
    compiled.packages.map((item) => [
      item.id,
      {
        implementationStatus: "NOT_STARTED",
        verificationStatus: "NOT_VERIFIED",
        evidenceRefs: [],
        evidenceHashes: [],
        verifiedAt: null,
        updatedAt: compiled.manifest.generated_at,
      },
    ]),
  );
  const submissions = [];
  const decisions = [];

  for (const event of journalState.events) {
    if (event.type === "WORK_PACKAGE_RECORDED") {
      packageState.set(event.payload.workPackageId, {
        implementationStatus: event.payload.implementationStatus,
        verificationStatus: event.payload.verificationStatus,
        evidenceRefs: event.payload.evidenceRefs,
        evidenceHashes: event.payload.evidenceHashes,
        verifiedAt:
          event.payload.verificationStatus === "VERIFIED"
            ? event.createdAt
            : null,
        updatedAt: event.createdAt,
      });
    } else if (event.type === "GATE_SUBMITTED") {
      submissions.push(event.payload);
    } else if (event.type === "GATE_DECIDED") {
      decisions.push(event.payload);
    }
  }

  function scopeForGate(gate) {
    return compiled.packages
      .filter(({ phase }) => phase === gate.phase)
      .map((item) => {
        const state = packageState.get(item.id);
        return {
          work_package_id: item.id,
          applicability: item.applicability,
          implementation_status: state.implementationStatus,
          verification_status: state.verificationStatus,
          evidence_refs: state.evidenceRefs,
          evidence_hashes: state.evidenceHashes,
        };
      });
  }

  function gateProjection(gate) {
    const scope = scopeForGate(gate);
    const unresolvedApplicability = scope
      .filter(({ applicability }) => applicability === "OPTIONAL")
      .map(({ work_package_id }) => work_package_id);
    const requiredIds =
      gate.phase === "P3"
        ? scope
            .filter(({ applicability }) => applicability === "REQUIRED")
            .map(({ work_package_id }) => work_package_id)
        : gate.required_work_packages;
    const missingWorkPackages = requiredIds.filter(
      (id) => packageState.get(id)?.verificationStatus !== "VERIFIED",
    );
    const gateSubmissions = submissions.filter(
      ({ gate_id }) => gate_id === gate.id,
    );
    const latestSubmission = gateSubmissions.at(-1) ?? null;
    const latestDecision = latestSubmission
      ? decisions.find(
          ({ submission_id }) =>
            submission_id === latestSubmission.submission_id,
        ) ?? null
      : null;
    const currentScopeMatches =
      !latestSubmission ||
      canonicalize(scope) ===
        canonicalize(latestSubmission.work_package_scope);

    let status = "NOT_READY";
    if (missingWorkPackages.length === 0 && unresolvedApplicability.length === 0) {
      status = "READY_TO_SUBMIT";
    }
    if (latestSubmission && currentScopeMatches) {
      status = latestDecision
        ? {
            APPROVE: "APPROVED",
            APPROVE_WITH_EXCLUSIONS: "APPROVED",
            RETURN: "RETURNED",
            HOLD: "HELD",
          }[latestDecision.decision]
        : "AWAITING_DECISION";
    } else if (
      latestSubmission &&
      latestDecision &&
      missingWorkPackages.length === 0 &&
      unresolvedApplicability.length === 0
    ) {
      status = "READY_TO_SUBMIT";
    } else if (latestSubmission) {
      status = "STALE_SUBMISSION";
    }

    return {
      id: gate.id,
      phase: gate.phase,
      opensPhase: gate.opens_phase ?? null,
      status,
      missingWorkPackages,
      unresolvedApplicability,
      latestSubmission,
      latestDecision,
      workPackageScope: scope,
    };
  }

  const gates = compiled.gates.map(gateProjection);
  const approvedGates = new Set(
    gates.filter(({ status }) => status === "APPROVED").map(({ id }) => id),
  );
  const phaseEntry = {
    P0: true,
    P1: approvedGates.has("G0"),
    P2: approvedGates.has("G0") && approvedGates.has("G1"),
    P3:
      approvedGates.has("G0") &&
      approvedGates.has("G1") &&
      approvedGates.has("G2"),
  };
  const requiredEntryGates = {
    P0: [],
    P1: ["G0"],
    P2: ["G0", "G1"],
    P3: ["G0", "G1", "G2"],
  };

  const workPackages = compiled.packages.map((item) => {
    const state = packageState.get(item.id);
    const structuralBlockers = [];
    for (const gateId of requiredEntryGates[item.phase]) {
      if (!approvedGates.has(gateId)) structuralBlockers.push(gateId);
    }
    for (const dependency of item.depends_on ?? []) {
      if (packageState.get(dependency)?.verificationStatus !== "VERIFIED") {
        structuralBlockers.push(dependency);
      }
    }
    for (const group of item.depends_on_any_of ?? []) {
      if (
        !group.some(
          (dependency) =>
            packageState.get(dependency)?.verificationStatus === "VERIFIED",
        )
      ) {
        structuralBlockers.push(group.join("|"));
      }
    }
    const structuralReady = structuralBlockers.length === 0;
    const startAuthorization = evaluateP2StartAuthorization({
      workPackageId: item.id,
      governanceEvents: journalState.events,
      policy: p2StartPolicy,
    });
    const authorizationBlockers = startAuthorization.reasonCodes;
    return {
      id: item.id,
      phase: item.phase,
      title: item.title,
      phaseEntryGate: item.phase_entry_gate,
      applicability: item.applicability,
      planStatus: item.plan_status,
      implementationStatus: state.implementationStatus,
      verificationStatus: state.verificationStatus,
      acceptanceAssertions: item.acceptance_assertions,
      responsibleRole: item.responsible_role,
      size: item.size,
      dependencies: item.depends_on ?? [],
      structuralReady,
      structuralBlockers,
      startAuthorization,
      authorizationBlockers,
      allowedToStart: structuralReady && startAuthorization.authorized,
      blockers: [...structuralBlockers, ...authorizationBlockers],
      evidenceRefs: state.evidenceRefs,
      evidenceHashes: state.evidenceHashes,
      verifiedAt: state.verifiedAt,
      updatedAt: state.updatedAt,
    };
  });

  function progress(items) {
    const verified = items.filter(
      ({ verificationStatus }) => verificationStatus === "VERIFIED",
    ).length;
    return {
      verified,
      total: items.length,
      percentage: items.length === 0 ? 0 : Math.round((verified / items.length) * 100),
    };
  }

  return {
    projectId: compiled.manifest.project_id,
    manifestVersion: compiled.manifest.manifest_version,
    revision: journalState.revision,
    evidenceValidationIssues,
    workPackages,
    gates,
    phaseEntry,
    progress: {
      product: progress(workPackages.filter(({ phase }) => phase !== "P3")),
      tenant: progress(
        workPackages.filter(
          ({ phase, applicability }) =>
            phase === "P3" && applicability === "REQUIRED",
        ),
      ),
      portfolio: progress(workPackages),
    },
    events: journalState.events,
  };
}

export function createMemoryJournal(initialEvents = []) {
  const events = initialEvents.map((event, index) => ({
    ...structuredClone(event),
    revision: event.revision ?? index + 1,
  }));

  return {
    async load() {
      return {
        revision: events.at(-1)?.revision ?? 0,
        events: structuredClone(events),
      };
    },
    async append({
      expectedRevision,
      idempotencyKey,
      commandHash,
      event,
    }) {
      const existing = events.find(
        (item) => item.idempotencyKey === idempotencyKey,
      );
      if (existing) {
        if (existing.commandHash !== commandHash) {
          fail(
            "IDEMPOTENCY_CONFLICT",
            "The idempotency key was already used for another command.",
          );
        }
        return { duplicate: true, event: structuredClone(existing) };
      }
      const revision = events.at(-1)?.revision ?? 0;
      if (expectedRevision !== revision) {
        fail("STALE_REVISION", "Project state changed; reload before retrying.");
      }
      const stored = {
        ...structuredClone(event),
        revision: revision + 1,
        idempotencyKey,
        commandHash,
      };
      events.push(stored);
      return { duplicate: false, event: structuredClone(stored) };
    },
  };
}

export function createProjectControl({
  manifest,
  journal,
  verifyFrozenEvidence = async () => false,
  verifyP2ExecutionBaseline = denyP2ExecutionBaseline,
  verifyP2ProfileReadiness = denyP2Readiness,
  verifyP2WorkPackageStartReadiness = denyP2Readiness,
  verifyReferenceReviewReadiness = denyReferenceReviewReadiness,
  p2ProfileReadinessPolicy = {},
  p2StartPolicy = {},
  referenceReviewPolicy = null,
  clock = () => new Date().toISOString(),
  idFactory = () => crypto.randomUUID(),
}) {
  if (!journal?.load || !journal?.append) {
    fail("INVALID_STORE", "A journal with load and append is required.");
  }
  const compiled = compileManifest(manifest);

  async function loadJournalState() {
    const journalState = await journal.load(compiled.manifest.project_id);
    const latestPackageEvents = new Map();
    for (const event of journalState.events) {
      if (event.type === "WORK_PACKAGE_RECORDED") {
        latestPackageEvents.set(event.payload.workPackageId, event);
      }
    }
    const evidenceValidationIssues = [];
    for (const event of latestPackageEvents.values()) {
      if (
        event.payload.verificationStatus === "VERIFIED" &&
        !(await verifyFrozenEvidence({
          workPackageId: event.payload.workPackageId,
          evidenceRefs: event.payload.evidenceRefs,
          evidenceHashes: event.payload.evidenceHashes,
        }))
      ) {
        evidenceValidationIssues.push({
          code: "EVIDENCE_NOT_FROZEN",
          workPackageId: event.payload.workPackageId,
          eventId: event.id,
          revision: event.revision,
        });
      }
    }
    return { journalState, evidenceValidationIssues };
  }

  async function snapshot() {
    const { journalState, evidenceValidationIssues } = await loadJournalState();
    return projectState(
      compiled,
      journalState,
      evidenceValidationIssues,
      p2StartPolicy,
    );
  }

  async function execute(context, command) {
    if (!hasRole(context, "PRODUCT_OWNER")) {
      fail("UNAUTHORIZED", "Only the Product Owner may change project governance.");
    }
    if (
      !command ||
      typeof command !== "object" ||
      !Number.isInteger(command.expectedRevision) ||
      typeof command.idempotencyKey !== "string" ||
      !command.idempotencyKey.trim()
    ) {
      fail("INVALID_COMMAND", "Revision and idempotency key are required.");
    }

    const commandHash = await sha256({
      actorId: context.actorId,
      command,
    });
    const { journalState, evidenceValidationIssues } = await loadJournalState();
    const duplicate = journalState.events.find(
      (event) => event.idempotencyKey === command.idempotencyKey,
    );
    if (duplicate) {
      if (duplicate.commandHash !== commandHash) {
        fail(
          "IDEMPOTENCY_CONFLICT",
          "The idempotency key was already used for another command.",
        );
      }
      return {
        revision: duplicate.revision,
        eventId: duplicate.id,
        duplicate: true,
        output: commandOutput(duplicate),
      };
    }
    if (journalState.revision !== command.expectedRevision) {
      fail("STALE_REVISION", "Project state changed; reload before retrying.");
    }

    const current = projectState(
      compiled,
      journalState,
      evidenceValidationIssues,
      p2StartPolicy,
    );
    function assertGateEvidenceHealthy(gate) {
      const phaseWorkPackageIds = new Set(
        compiled.packages
          .filter(({ phase }) => phase === gate.phase)
          .map(({ id }) => id),
      );
      const invalidWorkPackages = evidenceValidationIssues
        .filter(({ workPackageId }) => phaseWorkPackageIds.has(workPackageId))
        .map(({ workPackageId }) => workPackageId);
      if (invalidWorkPackages.length > 0) {
        fail(
          "EVIDENCE_NOT_FROZEN",
          `${gate.id} is blocked by unfrozen evidence: ${invalidWorkPackages.join(", ")}.`,
        );
      }
    }

    function assertGatePhaseEntered(gate) {
      if (!current.phaseEntry[gate.phase]) {
        fail(
          "GATE_PREDECESSOR_NOT_APPROVED",
          `${gate.id} cannot advance before every earlier gate is approved.`,
        );
      }
    }

    async function assertReferenceReviewReadiness(binding, message) {
      if (
        referenceReviewPolicy?.schemaVersion !==
          "reference-review-policy.v1" ||
        !(await readinessProved(
          verifyReferenceReviewReadiness,
          binding,
        ))
      ) {
        fail("REFERENCE_REVIEW_NOT_PROVED", message);
      }
    }

    let event;
    if (command.kind === "RECORD_WORK_PACKAGE") {
      assertNoUnknownCommandKeys(command, [
        "evidenceHashes",
        "evidenceRefs",
        "expectedRevision",
        "idempotencyKey",
        "implementationStatus",
        "kind",
        "note",
        "verificationStatus",
        "workPackageId",
      ]);
      const item = current.workPackages.find(
        ({ id }) => id === command.workPackageId,
      );
      if (!item) fail("UNKNOWN_ID", "Unknown work package.");
      if (!IMPLEMENTATION_STATUSES.includes(command.implementationStatus)) {
        fail("INVALID_COMMAND", "Invalid implementation status.");
      }
      if (!VERIFICATION_STATUSES.includes(command.verificationStatus)) {
        fail("INVALID_COMMAND", "Invalid verification status.");
      }
      assertStringArray(command.evidenceRefs ?? [], "evidenceRefs");
      assertStringArray(command.evidenceHashes ?? [], "evidenceHashes");
      const isEvidenceRevision =
        item.verificationStatus === "VERIFIED" &&
        command.implementationStatus === "IMPLEMENTED" &&
        command.verificationStatus === "VERIFIED" &&
        (canonicalize(item.evidenceRefs) !==
          canonicalize(command.evidenceRefs) ||
          canonicalize(item.evidenceHashes) !==
            canonicalize(command.evidenceHashes));
      if (
        (item.verificationStatus === "VERIFIED" && !isEvidenceRevision) ||
        IMPLEMENTATION_STATUSES.indexOf(command.implementationStatus) <
          IMPLEMENTATION_STATUSES.indexOf(item.implementationStatus)
      ) {
        fail("INVALID_TRANSITION", "Verified work cannot be overwritten or regressed.");
      }
      if (
        command.implementationStatus !== "NOT_STARTED" &&
        item.implementationStatus === "NOT_STARTED" &&
        !item.structuralReady
      ) {
        fail(
          "DEPENDENCY_BLOCKED",
          `Blocked by ${item.structuralBlockers.join(", ")}.`,
        );
      }
      if (
        command.implementationStatus !== "NOT_STARTED" &&
        item.startAuthorization.required &&
        !item.startAuthorization.authorized
      ) {
        fail(
          "EXECUTION_NOT_AUTHORIZED",
          `${item.id} has no valid D1 execution authorization: ${item.authorizationBlockers.join(", ")}.`,
        );
      }
      if (
        command.verificationStatus === "VERIFIED" &&
        (command.implementationStatus !== "IMPLEMENTED" ||
          command.evidenceRefs.length === 0 ||
          command.evidenceHashes.length === 0 ||
          command.evidenceHashes.some((hash) => !SHA256.test(hash)))
      ) {
        fail(
          "EVIDENCE_INCOMPLETE",
          "Verified work requires implementation and hashed evidence.",
        );
      }
      if (
        command.verificationStatus === "VERIFIED" &&
        !(await verifyFrozenEvidence({
          workPackageId: item.id,
          evidenceRefs: command.evidenceRefs,
          evidenceHashes: command.evidenceHashes,
        }))
      ) {
        fail(
          "EVIDENCE_NOT_FROZEN",
          "Verified work requires evidence frozen in the Git evidence catalog.",
        );
      }
      const referenceBoundary =
        command.verificationStatus === "VERIFIED"
          ? "IMPLEMENTATION_CONFORMANCE"
          : item.implementationStatus === "NOT_STARTED" &&
              command.implementationStatus !== "NOT_STARTED"
            ? "PRE_START"
            : null;
      if (referenceBoundary) {
        const activeProfile = journalState.events
          .filter(
            ({ type }) =>
              type === "P2_ACCEPTANCE_PROFILE_APPROVED",
          )
          .at(-1)?.payload;
        await assertReferenceReviewReadiness(
          {
            boundary: referenceBoundary,
            executionBaselineDigest:
              activeProfile?.execution_baseline_digest ??
              referenceReviewPolicy?.profileBinding
                ?.executionBaselineDigest ??
              null,
            profileApprovalId:
              activeProfile?.profile_approval_id ?? null,
            profileSha256:
              activeProfile?.profile_sha256 ??
              referenceReviewPolicy?.profileBinding?.profileSha256 ??
              null,
            sourceCommit:
              activeProfile?.source_commit ??
              referenceReviewPolicy?.profileBinding?.sourceCommit ??
              null,
            workPackageId: item.id,
          },
          `${item.id} requires its server-owned, Git-frozen Reference Review proof before ${referenceBoundary}.`,
        );
      }
      event = {
        id: idFactory(),
        type: "WORK_PACKAGE_RECORDED",
        actorId: context.actorId,
        createdAt: clock(),
        payload: {
          workPackageId: item.id,
          implementationStatus: command.implementationStatus,
          verificationStatus: command.verificationStatus,
          evidenceRefs: command.evidenceRefs,
          evidenceHashes: command.evidenceHashes,
          note: command.note ?? "",
        },
      };
    } else if (command.kind === "SUBMIT_GATE") {
      const gate = current.gates.find(({ id }) => id === command.gateId);
      if (!gate) fail("UNKNOWN_ID", "Unknown stage gate.");
      assertGateEvidenceHealthy(gate);
      assertGatePhaseEntered(gate);
      if (gate.status !== "READY_TO_SUBMIT") {
        fail("GATE_NOT_READY", `${gate.id} is ${gate.status}.`);
      }
      assertStringArray(command.evidenceRefs ?? [], "evidenceRefs");
      if (command.evidenceRefs.length === 0) {
        fail("EVIDENCE_INCOMPLETE", "A gate submission needs evidence.");
      }
      if (
        gate.latestSubmission &&
        command.supersedes !== gate.latestSubmission.submission_id
      ) {
        fail(
          "INVALID_SUPERSEDES",
          "A replacement submission must name the latest submission.",
        );
      }
      if (!gate.latestSubmission && command.supersedes) {
        fail("INVALID_SUPERSEDES", "The first submission cannot supersede another.");
      }
      const frozenPackage = {
        manifest_version: current.manifestVersion,
        gate_id: gate.id,
        source_revision: current.revision,
        work_package_scope: gate.workPackageScope,
        evidence_refs: command.evidenceRefs,
      };
      const packageHash = await sha256(frozenPackage);
      if (
        gate.latestSubmission &&
        packageHash === gate.latestSubmission.package_hash
      ) {
        fail("UNCHANGED_SUBMISSION", "A replacement submission must change the package.");
      }
      event = {
        id: idFactory(),
        type: "GATE_SUBMITTED",
        actorId: context.actorId,
        createdAt: clock(),
        payload: {
          gate_id: gate.id,
          submission_id: idFactory(),
          package_hash: packageHash,
          submitted_at: clock(),
          submitted_by: context.actorId,
          source_revision: current.revision,
          work_package_scope: gate.workPackageScope,
          evidence_refs: command.evidenceRefs,
          supersedes: command.supersedes ?? null,
        },
      };
    } else if (command.kind === "DECIDE_GATE") {
      const submission = current.gates
        .map(({ latestSubmission }) => latestSubmission)
        .find(
          (item) => item?.submission_id === command.submissionId,
        );
      if (!submission) fail("UNKNOWN_ID", "Unknown gate submission.");
      const existingDecision = current.gates
        .map(({ latestDecision }) => latestDecision)
        .find(
          (item) => item?.submission_id === command.submissionId,
        );
      if (existingDecision) {
        fail("DECISION_EXISTS", "This submission already has a decision.");
      }
      if (submission.package_hash !== command.expectedPackageHash) {
        fail("HASH_MISMATCH", "The decision does not name the submitted hash.");
      }
      const gate = current.gates.find(({ id }) => id === submission.gate_id);
      assertGateEvidenceHealthy(gate);
      assertGatePhaseEntered(gate);
      if (
        canonicalize(gate.workPackageScope) !==
        canonicalize(submission.work_package_scope)
      ) {
        fail("STALE_SUBMISSION", "Work or evidence changed after submission.");
      }
      if (!DECISIONS.includes(command.decision)) {
        fail("INVALID_COMMAND", "Invalid gate decision.");
      }
      assertStringArray(command.acceptedExclusions ?? [], "acceptedExclusions");
      assertStringArray(command.evidenceRefs ?? [], "evidenceRefs");
      if (command.evidenceRefs.length === 0) {
        fail("EVIDENCE_INCOMPLETE", "A gate decision needs evidence.");
      }
      const gateDefinition = compiled.gateById.get(submission.gate_id);
      const permitted = new Set(gateDefinition.permitted_exclusions ?? []);
      if (
        command.decision === "APPROVE_WITH_EXCLUSIONS" &&
        (command.acceptedExclusions.length === 0 ||
          command.acceptedExclusions.some((item) => !permitted.has(item)))
      ) {
        fail("INVALID_EXCLUSION", "The gate does not permit these exclusions.");
      }
      if (
        command.decision !== "APPROVE_WITH_EXCLUSIONS" &&
        command.acceptedExclusions.length > 0
      ) {
        fail("INVALID_EXCLUSION", "Only APPROVE_WITH_EXCLUSIONS accepts exclusions.");
      }
      event = {
        id: idFactory(),
        type: "GATE_DECIDED",
        actorId: context.actorId,
        createdAt: clock(),
        payload: {
          decision_id: idFactory(),
          submission_id: submission.submission_id,
          package_hash: submission.package_hash,
          decision: command.decision,
          decided_by: context.actorId,
          decided_at: clock(),
          accepted_exclusions: command.acceptedExclusions,
          evidence_refs: command.evidenceRefs,
        },
      };
    } else if (command.kind === "APPROVE_P2_ACCEPTANCE_PROFILE") {
      assertExactCommandKeys(command, [
        "executionBaselineDigest",
        "expectedRevision",
        "idempotencyKey",
        "kind",
        "profilePath",
        "profileSchemaVersion",
        "profileSha256",
        "receiptSchemaPath",
        "receiptSchemaSha256",
        "receiptSchemaVersion",
        "sourceCommit",
        "supersedes",
        "validatorPath",
        "validatorSha256",
        "validatorVersion",
      ]);
      if (!current.phaseEntry.P2) {
        fail(
          "GATE_PREDECESSOR_NOT_APPROVED",
          "P2 Profile cannot be approved before G0 and G1.",
        );
      }
      if (
        command.profilePath !== p2StartPolicy?.profile?.path ||
        command.profileSha256 !== p2StartPolicy?.profile?.sha256 ||
        command.profileSchemaVersion !==
          p2StartPolicy?.profile?.schemaVersion ||
        command.receiptSchemaPath !== p2StartPolicy?.receiptSchema?.path ||
        command.receiptSchemaSha256 !==
          p2StartPolicy?.receiptSchema?.sha256 ||
        command.receiptSchemaVersion !==
          p2StartPolicy?.receiptSchema?.version ||
        command.validatorPath !== p2StartPolicy?.validator?.path ||
        command.validatorSha256 !== p2StartPolicy?.validator?.sha256 ||
        command.validatorVersion !== p2StartPolicy?.validator?.version ||
        !SHA256.test(command.executionBaselineDigest ?? "") ||
        !GIT_COMMIT.test(command.sourceCommit ?? "")
      ) {
        fail(
          "INVALID_COMMAND",
          "P2 Profile approval does not match the locally frozen candidate.",
        );
      }
      await assertReferenceReviewReadiness(
        {
          boundary: "PROFILE_APPROVAL",
          executionBaselineDigest: command.executionBaselineDigest,
          profileApprovalId: null,
          profileSha256: command.profileSha256,
          sourceCommit: command.sourceCommit,
          workPackageId: null,
        },
        "P2 Profile approval requires the server-owned Reference Review bundles bound to the exact Profile and execution baseline.",
      );
      if (
        !(await readinessProved(verifyP2ProfileReadiness, {
          profileSha256: command.profileSha256,
          supplementalEvidenceIndexSha256:
            p2ProfileReadinessPolicy.supplementalEvidenceIndexSha256,
          sourceCommit: command.sourceCommit,
          executionBaselineDigest: command.executionBaselineDigest,
        }))
      ) {
        fail(
          "P2_PROFILE_READINESS_NOT_PROVED",
          "P2 Profile approval requires a closed, hash-bound supplemental evidence index.",
        );
      }
      let executionBaselineVerified = false;
      try {
        executionBaselineVerified = await verifyP2ExecutionBaseline({
          executionBaselineDigest: command.executionBaselineDigest,
          sourceCommit: command.sourceCommit,
          policy: p2StartPolicy,
        });
      } catch {
        executionBaselineVerified = false;
      }
      if (executionBaselineVerified !== true) {
        fail(
          "P2_EXECUTION_BASELINE_UNVERIFIED",
          "The execution baseline descriptor is missing, malformed, or does not bind the frozen candidate.",
        );
      }
      const previousProfileApproval = journalState.events
        .filter(
          ({ type }) => type === "P2_ACCEPTANCE_PROFILE_APPROVED",
        )
        .at(-1)?.payload;
      if (
        command.supersedes !==
        (previousProfileApproval?.profile_approval_id ?? null)
      ) {
        fail(
          "INVALID_SUPERSEDES",
          "A Profile approval must supersede the current approval exactly.",
        );
      }
      const recordedAt = clock();
      event = {
        id: idFactory(),
        type: "P2_ACCEPTANCE_PROFILE_APPROVED",
        actorId: context.actorId,
        createdAt: recordedAt,
        payload: {
          profile_approval_id: governedId("p2pa", idFactory()),
          profile_path: command.profilePath,
          profile_sha256: command.profileSha256,
          profile_schema_version: command.profileSchemaVersion,
          receipt_schema_path: command.receiptSchemaPath,
          receipt_schema_sha256: command.receiptSchemaSha256,
          receipt_schema_version: command.receiptSchemaVersion,
          validator_path: command.validatorPath,
          validator_sha256: command.validatorSha256,
          validator_version: command.validatorVersion,
          execution_baseline_digest: command.executionBaselineDigest,
          source_commit: command.sourceCommit,
          approved_by: context.actorId,
          approved_at: recordedAt,
          source_revision: command.expectedRevision,
          supersedes: command.supersedes,
        },
      };
    } else if (command.kind === "AUTHORIZE_P2_WORK_PACKAGE_START") {
      assertExactCommandKeys(command, [
        "executionBaselineDigest",
        "expectedRevision",
        "idempotencyKey",
        "kind",
        "profileApprovalId",
        "workPackageId",
      ]);
      const item = current.workPackages.find(
        ({ id }) => id === command.workPackageId,
      );
      if (!item || !item.startAuthorization.required) {
        fail("UNKNOWN_ID", "Only O02 and O03 use P2 start authorization.");
      }
      if (!item.structuralReady) {
        fail(
          "DEPENDENCY_BLOCKED",
          `Blocked by ${item.structuralBlockers.join(", ")}.`,
        );
      }
      if (
        item.startAuthorization.profileStatus !== "APPROVED" ||
        item.startAuthorization.profileApprovalId !==
          command.profileApprovalId ||
        item.startAuthorization.executionBaselineDigest !==
          command.executionBaselineDigest
      ) {
        fail(
          "P2_PROFILE_BINDING_MISMATCH",
          "Start authorization must bind the current approved Profile and execution baseline.",
        );
      }
      if (item.startAuthorization.executionStatus === "AUTHORIZED") {
        fail(
          "P2_START_AUTHORIZATION_EXISTS",
          "This work package already has a current start authorization.",
        );
      }
      const activeProfile = journalState.events
        .filter(
          ({ type }) => type === "P2_ACCEPTANCE_PROFILE_APPROVED",
        )
        .at(-1)?.payload;
      if (
        !activeProfile ||
        activeProfile.profile_approval_id !== command.profileApprovalId
      ) {
        fail(
          "P2_PROFILE_BINDING_MISMATCH",
          "The active Profile approval is unavailable.",
        );
      }
      await assertReferenceReviewReadiness(
        {
          boundary: "DEPENDENCY_ADOPTION",
          executionBaselineDigest:
            activeProfile.execution_baseline_digest,
          profileApprovalId: activeProfile.profile_approval_id,
          profileSha256: activeProfile.profile_sha256,
          sourceCommit: activeProfile.source_commit,
          workPackageId: item.id,
        },
        `${item.id} start authorization requires its server-owned, Git-frozen Reference Review bundle.`,
      );
      if (
        !(await readinessProved(verifyP2WorkPackageStartReadiness, {
          workPackageId: item.id,
          profileApprovalId: activeProfile.profile_approval_id,
          profileSha256: activeProfile.profile_sha256,
          sourceCommit: activeProfile.source_commit,
          executionBaselineDigest:
            activeProfile.execution_baseline_digest,
        }))
      ) {
        fail(
          "P2_WORK_PACKAGE_START_READINESS_NOT_PROVED",
          `${item.id} start authorization requires its selected, versioned and digested tool locks.`,
        );
      }
      const recordedAt = clock();
      event = {
        id: idFactory(),
        type: "P2_WORK_PACKAGE_START_AUTHORIZED",
        actorId: context.actorId,
        createdAt: recordedAt,
        payload: {
          authorization_id: governedId("p2wpa", idFactory()),
          work_package_id: item.id,
          profile_approval_id: activeProfile.profile_approval_id,
          profile_sha256: activeProfile.profile_sha256,
          execution_baseline_digest:
            activeProfile.execution_baseline_digest,
          authorization_status: "AUTHORIZED",
          revokes_authorization_id: null,
          recorded_by: context.actorId,
          recorded_at: recordedAt,
          source_revision: command.expectedRevision,
        },
      };
    } else if (
      command.kind === "REVOKE_P2_WORK_PACKAGE_START_AUTHORIZATION"
    ) {
      assertExactCommandKeys(command, [
        "executionBaselineDigest",
        "expectedRevision",
        "idempotencyKey",
        "kind",
        "profileApprovalId",
        "revokesAuthorizationId",
        "workPackageId",
      ]);
      const item = current.workPackages.find(
        ({ id }) => id === command.workPackageId,
      );
      const latestAuthorization = journalState.events
        .filter(
          ({ type, payload }) =>
            type === "P2_WORK_PACKAGE_START_AUTHORIZED" &&
            payload.work_package_id === command.workPackageId,
        )
        .at(-1)?.payload;
      if (
        !item?.startAuthorization.required ||
        item.startAuthorization.executionStatus !== "AUTHORIZED" ||
        item.startAuthorization.profileApprovalId !==
          command.profileApprovalId ||
        item.startAuthorization.executionBaselineDigest !==
          command.executionBaselineDigest ||
        latestAuthorization?.authorization_id !==
          command.revokesAuthorizationId
      ) {
        fail(
          "P2_START_AUTHORIZATION_MISMATCH",
          "Only the current exact start authorization can be revoked.",
        );
      }
      const recordedAt = clock();
      event = {
        id: idFactory(),
        type: "P2_WORK_PACKAGE_START_AUTHORIZED",
        actorId: context.actorId,
        createdAt: recordedAt,
        payload: {
          authorization_id: governedId("p2wpa", idFactory()),
          work_package_id: item.id,
          profile_approval_id: command.profileApprovalId,
          profile_sha256: p2StartPolicy.profile.sha256,
          execution_baseline_digest: command.executionBaselineDigest,
          authorization_status: "REVOKED",
          revokes_authorization_id: command.revokesAuthorizationId,
          recorded_by: context.actorId,
          recorded_at: recordedAt,
          source_revision: command.expectedRevision,
        },
      };
    } else {
      fail("INVALID_COMMAND", "Unknown governance command.");
    }

    const result = await journal.append({
      projectId: compiled.manifest.project_id,
      expectedRevision: command.expectedRevision,
      idempotencyKey: command.idempotencyKey,
      commandHash,
      event,
    });
    return {
      revision: result.event.revision,
      eventId: result.event.id,
      duplicate: result.duplicate,
      output: commandOutput(result.event),
    };
  }

  return Object.freeze({ snapshot, execute });
}
