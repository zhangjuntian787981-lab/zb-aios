import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "../lib/project-control.mjs";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const canonicalJson = canonicalizeProjectJson(value);
const canonicalBytes = Buffer.from(canonicalJson, "utf8");

process.stdout.write(
  JSON.stringify({
    pid: process.pid,
    nodeVersion: process.version,
    platform: process.platform,
    architecture: process.arch,
    canonicalUtf8Hex: canonicalBytes.toString("hex"),
    canonicalBytesSha256: await sha256ProjectValue(value),
  }),
);
