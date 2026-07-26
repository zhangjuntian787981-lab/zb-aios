export class C14SyntheticDataPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C14SyntheticDataPolicyError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C14SyntheticDataPolicyError(code, message);
}

export function createC14SyntheticDataPolicyResolver(document) {
  if (
    document?.schemaVersion !== "1.0.0" ||
    document?.phase !== "P1_SYNTHETIC_ONLY" ||
    document?.dataClassification !== "SYNTHETIC_ONLY" ||
    !Array.isArray(document?.entries) ||
    document.entries.length < 1
  ) {
    fail("INVALID_FIXTURE", "C14 data policy fixture is invalid.");
  }
  const entries = new Map();
  for (const entry of document.entries) {
    if (
      typeof entry?.inputRef !== "string" ||
      typeof entry?.inputSha256 !== "string" ||
      entries.has(entry.inputRef)
    ) {
      fail("INVALID_FIXTURE", "C14 data policy entry is invalid.");
    }
    entries.set(entry.inputRef, Object.freeze(structuredClone(entry)));
  }
  return Object.freeze({
    async resolve({ inputRef, inputSha256 }) {
      const entry = entries.get(inputRef);
      if (!entry || entry.inputSha256 !== inputSha256) {
        fail(
          "INPUT_NOT_REGISTERED",
          "C14 input is not a frozen Synthetic fixture.",
        );
      }
      return Object.freeze({
        trustSource: "C14_SYNTHETIC_DATA_POLICY",
        ...structuredClone(entry),
      });
    },
  });
}
