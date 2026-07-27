import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("progress API applies and projects the deny-first P2 start boundary", async () => {
  const source = await readFile(
    new URL("../app/api/progress/route.ts", import.meta.url),
    "utf8",
  );

  assert.match(source, /P2_V2_CANDIDATE_START_POLICY/);
  assert.match(
    source,
    /p2StartPolicy:\s*P2_V2_CANDIDATE_START_POLICY/,
  );
  assert.match(source, /structuralReady:\s*item\.structuralReady/);
  assert.match(source, /structuralBlockers:\s*item\.structuralBlockers/);
  assert.match(source, /startAuthorization:\s*item\.startAuthorization/);
  assert.match(source, /EXECUTION_NOT_AUTHORIZED/);
  assert.match(source, /P2_PROFILE_BINDING_MISMATCH/);
  assert.match(source, /P2_START_AUTHORIZATION_EXISTS/);
  assert.match(source, /P2_START_AUTHORIZATION_MISMATCH/);
  assert.match(source, /P2_EXECUTION_BASELINE_UNVERIFIED/);
  assert.match(source, /code:\s*stableErrorCode\(error\)/);

  assert.doesNotMatch(source, /approve_p2_acceptance_profile/i);
  assert.doesNotMatch(source, /authorize_p2_work_package_start/i);
  assert.doesNotMatch(source, /revoke_p2_work_package_start/i);
});
