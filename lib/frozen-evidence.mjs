const SHA256 = /^sha256:[a-f0-9]{64}$/;

function validStringArray(value) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((item) => typeof item === "string" && item.length > 0)
  );
}

function sameArray(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

export function createFrozenEvidenceVerifier(catalog) {
  if (
    catalog?.schemaVersion !== "frozen-evidence-catalog.v1" ||
    !Array.isArray(catalog.records)
  ) {
    throw new Error("Invalid frozen evidence catalog.");
  }

  const records = catalog.records.map((record) => {
    if (
      typeof record?.workPackageId !== "string" ||
      !validStringArray(record.evidenceRefs) ||
      !validStringArray(record.evidenceHashes) ||
      record.evidenceHashes.some((hash) => !SHA256.test(hash))
    ) {
      throw new Error("Invalid frozen evidence record.");
    }
    return structuredClone(record);
  });

  return async ({ workPackageId, evidenceRefs, evidenceHashes }) =>
    records.some(
      (record) =>
        record.workPackageId === workPackageId &&
        sameArray(record.evidenceRefs, evidenceRefs) &&
        sameArray(record.evidenceHashes, evidenceHashes),
    );
}
