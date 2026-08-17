import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import {
  createP2ExecutionBaselineVerifier,
  p2AcceptanceDigests,
} from "../lib/p2-acceptance-receipt-validator.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";

const execFileAsync = promisify(execFile);
const RECIPE_PATH =
  "implementation/p2/acceptance/p2-execution-baseline-recipe.v1.json";
const FINAL_RECIPE_PATH =
  "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json";
const PROFILE_PATH =
  "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json";
const FINAL_PROFILE_PATH =
  "implementation/p2/acceptance/p2-acceptance-profile.v2.json";
const RECEIPT_SCHEMA_PATH =
  "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json";
const VALIDATOR_PATH = "lib/p2-acceptance-receipt-validator.mjs";
const FIXTURE_PATH =
  "implementation/p1/c06/synthetic-authorization-fixtures.v1.json";
const TOOL_LOCK_PATH = "package-lock.json";

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

async function git(repositoryPath, args, options = {}) {
  return execFileAsync("git", args, {
    cwd: repositoryPath,
    encoding: "utf8",
    ...options,
  });
}

async function writeRepositoryFile(repositoryPath, path, bytes) {
  const absolutePath = join(repositoryPath, path);
  await mkdir(dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, bytes);
}

function descriptorFromRecipe(sourceCommit, recipe) {
  return {
    schemaVersion: "p2-execution-baseline.v1",
    sourceCommit,
    acceptanceProfile: recipe.acceptanceProfile,
    receiptSchema: recipe.receiptSchema,
    semanticValidator: recipe.semanticValidator,
    fixtures: recipe.fixtures,
    toolLocks: recipe.toolLocks.map(({ name, sha256, version }) => ({
      name,
      version,
      digest: sha256,
    })),
  };
}

async function createFrozenBaselineRepository({
  commitAt = "2026-07-28T01:00:00Z",
  omittedPath = null,
  profileHashOverride = null,
  profileRecordedAt = "2026-07-28T00:00:00.000Z",
  profilePath = PROFILE_PATH,
  recipePath = RECIPE_PATH,
} = {}) {
  const repositoryPath = await mkdtemp(
    join(tmpdir(), "p2-execution-baseline-git-"),
  );
  await git(repositoryPath, ["init", "-q"]);
  await git(repositoryPath, ["config", "user.name", "P2 Test"]);
  await git(repositoryPath, ["config", "user.email", "p2-test@example.invalid"]);

  const subjects = {
    [profilePath]: jsonBytes({
      schemaVersion: "p2-acceptance-profile.v2",
      recordedAt: profileRecordedAt,
    }),
    [RECEIPT_SCHEMA_PATH]: jsonBytes({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
    }),
    [VALIDATOR_PATH]: Buffer.from(
      'export const version = "p2-acceptance-validator.v2";\n',
    ),
    [FIXTURE_PATH]: jsonBytes({
      scope_kind: "SYNTHETIC",
      cases: [{ id: "fixture-01" }],
    }),
    [TOOL_LOCK_PATH]: jsonBytes({
      lockfileVersion: 3,
      packages: {},
    }),
  };
  const recipe = {
    schemaVersion: "p2-execution-baseline-recipe.v1",
    acceptanceProfile: {
      path: profilePath,
      sha256:
        profileHashOverride ?? sha256(subjects[profilePath]),
    },
    receiptSchema: {
      path: RECEIPT_SCHEMA_PATH,
      version: "p2-acceptance-receipt.v2",
      sha256: sha256(subjects[RECEIPT_SCHEMA_PATH]),
    },
    semanticValidator: {
      path: VALIDATOR_PATH,
      version: "p2-acceptance-validator.v2",
      sha256: sha256(subjects[VALIDATOR_PATH]),
    },
    fixtures: [
      {
        name: "synthetic-authorization",
        path: FIXTURE_PATH,
        sha256: sha256(subjects[FIXTURE_PATH]),
      },
    ],
    toolLocks: [
      {
        name: "npm-package-lock",
        path: TOOL_LOCK_PATH,
        version: "3",
        sha256: sha256(subjects[TOOL_LOCK_PATH]),
      },
    ],
  };
  const recipeBytes = jsonBytes(recipe);
  subjects[recipePath] = recipeBytes;

  for (const [path, bytes] of Object.entries(subjects)) {
    if (path !== omittedPath) {
      await writeRepositoryFile(repositoryPath, path, bytes);
    }
  }
  await git(repositoryPath, ["add", "--all"]);
  await git(repositoryPath, ["commit", "-q", "-m", "freeze baseline"], {
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: commitAt,
      GIT_COMMITTER_DATE: commitAt,
    },
  });
  const sourceCommit = (
    await git(repositoryPath, ["rev-parse", "HEAD"])
  ).stdout.trim();
  const policy = {
    executionBaselineRecipe: {
      path: recipePath,
      schemaVersion: recipe.schemaVersion,
      sha256: sha256(recipeBytes),
    },
    profile: {
      path: profilePath,
      schemaVersion: "p2-acceptance-profile.v2",
      sha256: recipe.acceptanceProfile.sha256,
    },
    receiptSchema: structuredClone(recipe.receiptSchema),
    validator: {
      path: recipe.semanticValidator.path,
      version: recipe.semanticValidator.version,
      sha256: recipe.semanticValidator.sha256,
    },
  };
  const descriptor = descriptorFromRecipe(sourceCommit, recipe);

  return {
    descriptor,
    executionBaselineDigest:
      p2AcceptanceDigests.executionBaseline(descriptor),
    policy,
    recipe,
    repositoryPath,
    sourceCommit,
    subjects,
    async cleanup() {
      await rm(repositoryPath, { recursive: true, force: true });
    },
  };
}

test("execution baseline verification reads every subject from one real Git commit", async (t) => {
  const frozen = await createFrozenBaselineRepository();
  const finalFrozen = await createFrozenBaselineRepository({
    profilePath: FINAL_PROFILE_PATH,
    recipePath: FINAL_RECIPE_PATH,
  });
  t.after(frozen.cleanup);
  t.after(finalFrozen.cleanup);
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });
  const verifyFinal = createP2ExecutionBaselineVerifier({
    repositoryPath: finalFrozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest: frozen.executionBaselineDigest,
      sourceCommit: frozen.sourceCommit,
      policy: frozen.policy,
    }),
    true,
  );
  assert.equal(
    await verifyFinal({
      executionBaselineDigest: finalFrozen.executionBaselineDigest,
      sourceCommit: finalFrozen.sourceCommit,
      policy: finalFrozen.policy,
    }),
    true,
  );

  const crossedPolicy = {
    ...finalFrozen.policy,
    executionBaselineRecipe: structuredClone(
      frozen.policy.executionBaselineRecipe,
    ),
  };
  assert.equal(
    await verifyFinal({
      executionBaselineDigest: finalFrozen.executionBaselineDigest,
      sourceCommit: finalFrozen.sourceCommit,
      policy: crossedPolicy,
    }),
    false,
  );
});

test("a nonexistent source commit, including all ones, cannot verify", async (t) => {
  const frozen = await createFrozenBaselineRepository();
  t.after(frozen.cleanup);
  const nonexistentCommit = "1111111111111111111111111111111111111111";
  const forgedDescriptor = {
    ...frozen.descriptor,
    sourceCommit: nonexistentCommit,
  };
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest:
        p2AcceptanceDigests.executionBaseline(forgedDescriptor),
      sourceCommit: nonexistentCommit,
      policy: frozen.policy,
    }),
    false,
  );
});

test("Git control environment cannot redirect verification to another repository", async (t) => {
  const expectedRepository = await createFrozenBaselineRepository();
  const redirectedRepository = await createFrozenBaselineRepository({
    commitAt: "2026-07-28T02:00:00Z",
    profileRecordedAt: "2026-07-28T01:30:00.000Z",
  });
  t.after(expectedRepository.cleanup);
  t.after(redirectedRepository.cleanup);
  const previousGitDir = process.env.GIT_DIR;
  process.env.GIT_DIR = join(redirectedRepository.repositoryPath, ".git");
  t.after(() => {
    if (previousGitDir === undefined) {
      delete process.env.GIT_DIR;
    } else {
      process.env.GIT_DIR = previousGitDir;
    }
  });
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: expectedRepository.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest:
        redirectedRepository.executionBaselineDigest,
      sourceCommit: redirectedRepository.sourceCommit,
      policy: redirectedRepository.policy,
    }),
    false,
  );
});

test("ambient PATH cannot replace the trusted Git executable", async (t) => {
  const frozen = await createFrozenBaselineRepository();
  t.after(frozen.cleanup);
  const fakeBin = await mkdtemp(join(tmpdir(), "p2-fake-git-bin-"));
  t.after(() => rm(fakeBin, { recursive: true, force: true }));
  const fakeGitPath = join(fakeBin, "git");
  const escapedRepositoryPath = frozen.repositoryPath.replaceAll(
    "'",
    "'\\''",
  );
  await writeFile(
    fakeGitPath,
    `#!/bin/sh
repository_path='${escapedRepositoryPath}'
if [ "$2" = "cat-file" ] && [ "$3" = "-t" ]; then
  printf 'commit\\n'
  exit 0
fi
if [ "$2" = "cat-file" ] && [ "$3" = "blob" ]; then
  subject_path="\${4#*:}"
  /bin/cat "$repository_path/$subject_path"
  exit $?
fi
if [ "$2" = "show" ]; then
  printf '2026-07-28T01:00:00+00:00\\n'
  exit 0
fi
exit 1
`,
  );
  await chmod(fakeGitPath, 0o755);
  const previousPath = process.env.PATH;
  process.env.PATH = fakeBin;
  t.after(() => {
    if (previousPath === undefined) {
      delete process.env.PATH;
    } else {
      process.env.PATH = previousPath;
    }
  });
  const nonexistentCommit = "1111111111111111111111111111111111111111";
  const forgedDescriptor = {
    ...frozen.descriptor,
    sourceCommit: nonexistentCommit,
  };
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest:
        p2AcceptanceDigests.executionBaseline(forgedDescriptor),
      sourceCommit: nonexistentCommit,
      policy: frozen.policy,
    }),
    false,
  );
});

test("an annotated tag object cannot impersonate a source commit", async (t) => {
  const frozen = await createFrozenBaselineRepository();
  t.after(frozen.cleanup);
  await git(frozen.repositoryPath, [
    "tag",
    "-a",
    "baseline-tag",
    "-m",
    "annotated baseline tag",
  ]);
  const tagObject = (
    await git(frozen.repositoryPath, ["rev-parse", "baseline-tag^{tag}"])
  ).stdout.trim();
  const taggedDescriptor = {
    ...frozen.descriptor,
    sourceCommit: tagObject,
  };
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest:
        p2AcceptanceDigests.executionBaseline(taggedDescriptor),
      sourceCommit: tagObject,
      policy: frozen.policy,
    }),
    false,
  );
});

test("an execution baseline cannot cite a path absent from its source commit", async (t) => {
  const frozen = await createFrozenBaselineRepository({
    omittedPath: FIXTURE_PATH,
  });
  t.after(frozen.cleanup);
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest: frozen.executionBaselineDigest,
      sourceCommit: frozen.sourceCommit,
      policy: frozen.policy,
    }),
    false,
  );
});

test("a recipe hash cannot replace the exact bytes stored in its source commit", async (t) => {
  const frozen = await createFrozenBaselineRepository({
    profileHashOverride: `sha256:${"f".repeat(64)}`,
  });
  t.after(frozen.cleanup);
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest: frozen.executionBaselineDigest,
      sourceCommit: frozen.sourceCommit,
      policy: frozen.policy,
    }),
    false,
  );
});

test("modified working-tree files cannot impersonate source-commit bytes", async (t) => {
  const frozen = await createFrozenBaselineRepository();
  t.after(frozen.cleanup);
  const forgedProfileBytes = jsonBytes({
    schemaVersion: "p2-acceptance-profile.v2",
    recordedAt: "2026-07-28T00:30:00.000Z",
    forged: true,
  });
  const forgedRecipe = structuredClone(frozen.recipe);
  forgedRecipe.acceptanceProfile.sha256 = sha256(forgedProfileBytes);
  const forgedRecipeBytes = jsonBytes(forgedRecipe);
  await writeRepositoryFile(
    frozen.repositoryPath,
    PROFILE_PATH,
    forgedProfileBytes,
  );
  await writeRepositoryFile(
    frozen.repositoryPath,
    RECIPE_PATH,
    forgedRecipeBytes,
  );
  const forgedPolicy = {
    ...frozen.policy,
    executionBaselineRecipe: {
      ...frozen.policy.executionBaselineRecipe,
      sha256: sha256(forgedRecipeBytes),
    },
    profile: {
      ...frozen.policy.profile,
      sha256: sha256(forgedProfileBytes),
    },
  };
  const forgedDescriptor = descriptorFromRecipe(
    frozen.sourceCommit,
    forgedRecipe,
  );
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest:
        p2AcceptanceDigests.executionBaseline(forgedDescriptor),
      sourceCommit: frozen.sourceCommit,
      policy: forgedPolicy,
    }),
    false,
  );
});

test("a Profile recorded after its source commit cannot verify", async (t) => {
  const frozen = await createFrozenBaselineRepository({
    commitAt: "2026-07-28T01:00:00Z",
    profileRecordedAt: "2026-07-28T01:00:00.001Z",
  });
  t.after(frozen.cleanup);
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });

  assert.equal(
    await verify({
      executionBaselineDigest: frozen.executionBaselineDigest,
      sourceCommit: frozen.sourceCommit,
      policy: frozen.policy,
    }),
    false,
  );
});

test("the Git recipe itself is read from its deterministic source-commit path", async (t) => {
  const frozen = await createFrozenBaselineRepository();
  t.after(frozen.cleanup);
  const verify = createP2ExecutionBaselineVerifier({
    repositoryPath: frozen.repositoryPath,
  });
  const recipeBytes = await readFile(
    join(frozen.repositoryPath, RECIPE_PATH),
  );
  const wrongPathPolicy = {
    ...frozen.policy,
    executionBaselineRecipe: {
      ...frozen.policy.executionBaselineRecipe,
      path: "implementation/p2/acceptance/missing-recipe.v1.json",
      sha256: sha256(recipeBytes),
    },
  };

  assert.equal(
    await verify({
      executionBaselineDigest: frozen.executionBaselineDigest,
      sourceCommit: frozen.sourceCommit,
      policy: wrongPathPolicy,
    }),
    false,
  );

  const arbitraryPathPolicy = {
    ...frozen.policy,
    executionBaselineRecipe: {
      ...frozen.policy.executionBaselineRecipe,
      path: "implementation/p2/acceptance/another-recipe.v1.json",
    },
  };
  assert.equal(
    await verify({
      executionBaselineDigest: frozen.executionBaselineDigest,
      sourceCommit: frozen.sourceCommit,
      policy: arbitraryPathPolicy,
    }),
    false,
  );
});

test("the repository Final Profile verifies only after its exact recipe is Git frozen", async (t) => {
  const repositoryPath = new URL("../", import.meta.url).pathname;
  const { stdout: revisionOutput } = await git(repositoryPath, [
    "rev-list",
    "-1",
    "HEAD",
    "--",
    FINAL_RECIPE_PATH,
  ]);
  const sourceCommit = revisionOutput.trim();
  if (!sourceCommit) {
    t.skip("Final Profile recipe is not frozen in the current HEAD yet.");
    return;
  }
  const { stdout: recipeBytes } = await execFileAsync(
    "git",
    [
      "--no-replace-objects",
      "cat-file",
      "blob",
      `${sourceCommit}:${FINAL_RECIPE_PATH}`,
    ],
    {
      cwd: repositoryPath,
      encoding: null,
    },
  );
  const recipe = JSON.parse(Buffer.from(recipeBytes).toString("utf8"));
  const descriptor = descriptorFromRecipe(sourceCommit, recipe);
  const verify = createP2ExecutionBaselineVerifier({ repositoryPath });

  assert.equal(
    await verify({
      executionBaselineDigest:
        p2AcceptanceDigests.executionBaseline(descriptor),
      sourceCommit,
      policy: P2_V2_CANDIDATE_START_POLICY,
    }),
    true,
  );

  const finalRecipeBytes = await readFile(
    join(repositoryPath, FINAL_RECIPE_PATH),
  );
  const finalRecipe = JSON.parse(finalRecipeBytes);
  assert.deepEqual(Object.keys(finalRecipe).sort(), [
    "acceptanceProfile",
    "fixtures",
    "receiptSchema",
    "schemaVersion",
    "semanticValidator",
    "toolLocks",
  ]);
  assert.equal(finalRecipe.schemaVersion, "p2-execution-baseline-recipe.v1");
  assert.equal(Object.hasOwn(finalRecipe, "sourceCommit"), false);
  assert.equal(Object.hasOwn(finalRecipe, "executionBaselineDigest"), false);
  assert.equal(Object.hasOwn(finalRecipe, "sha256"), false);
  for (const subject of [
    finalRecipe.acceptanceProfile,
    finalRecipe.receiptSchema,
    finalRecipe.semanticValidator,
    ...finalRecipe.fixtures,
    ...finalRecipe.toolLocks,
  ]) {
    assert.equal(
      subject.sha256,
      sha256(await readFile(join(repositoryPath, subject.path))),
      subject.path,
    );
  }

  const unknownFieldRepository = await createFrozenBaselineRepository({
    profilePath: FINAL_PROFILE_PATH,
    recipePath: FINAL_RECIPE_PATH,
  });
  t.after(unknownFieldRepository.cleanup);
  const tamperedRecipe = {
    ...unknownFieldRepository.recipe,
    sourceCommit: unknownFieldRepository.sourceCommit,
  };
  const tamperedRecipeBytes = jsonBytes(tamperedRecipe);
  await writeRepositoryFile(
    unknownFieldRepository.repositoryPath,
    FINAL_RECIPE_PATH,
    tamperedRecipeBytes,
  );
  await git(unknownFieldRepository.repositoryPath, ["add", FINAL_RECIPE_PATH]);
  await git(unknownFieldRepository.repositoryPath, [
    "commit",
    "-q",
    "-m",
    "tamper recipe",
  ]);
  const tamperedCommit = (
    await git(unknownFieldRepository.repositoryPath, ["rev-parse", "HEAD"])
  ).stdout.trim();
  const verifyTampered = createP2ExecutionBaselineVerifier({
    repositoryPath: unknownFieldRepository.repositoryPath,
  });
  const tamperedDescriptor = descriptorFromRecipe(
    tamperedCommit,
    unknownFieldRepository.recipe,
  );
  assert.equal(
    await verifyTampered({
      executionBaselineDigest:
        p2AcceptanceDigests.executionBaseline(tamperedDescriptor),
      sourceCommit: tamperedCommit,
      policy: {
        ...unknownFieldRepository.policy,
        executionBaselineRecipe: {
          ...unknownFieldRepository.policy.executionBaselineRecipe,
          sha256: sha256(tamperedRecipeBytes),
        },
      },
    }),
    false,
  );
});
