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

function assertStringArray(value, field) {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || !item.trim())
  ) {
    fail("INVALID_MANIFEST", `${field} must be an array of non-empty strings.`);
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
  return {};
}

function projectState(compiled, journalState, evidenceValidationIssues = []) {
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
    const blockers = [];
    for (const gateId of requiredEntryGates[item.phase]) {
      if (!approvedGates.has(gateId)) blockers.push(gateId);
    }
    for (const dependency of item.depends_on ?? []) {
      if (packageState.get(dependency)?.verificationStatus !== "VERIFIED") {
        blockers.push(dependency);
      }
    }
    for (const group of item.depends_on_any_of ?? []) {
      if (
        !group.some(
          (dependency) =>
            packageState.get(dependency)?.verificationStatus === "VERIFIED",
        )
      ) {
        blockers.push(group.join("|"));
      }
    }
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
      allowedToStart: blockers.length === 0,
      blockers,
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
    return projectState(compiled, journalState, evidenceValidationIssues);
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

    let event;
    if (command.kind === "RECORD_WORK_PACKAGE") {
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
        !item.allowedToStart
      ) {
        fail(
          "DEPENDENCY_BLOCKED",
          `Blocked by ${item.blockers.join(", ")}.`,
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
