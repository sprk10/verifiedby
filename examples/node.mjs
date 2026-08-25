// Node quickstart — embed an RFC 3161 timestamp / signature check in your
// own app.
//
//   npm install verifiedby
//   node examples/node.mjs path/to/document.pdf
//
// Requires Node 20+ (crypto.subtle is global from Node 20 onward; earlier
// versions do not expose it and this will throw ReferenceError: crypto is
// not defined).

import { readFileSync } from "node:fs";
import { verify } from "verifiedby";

const path = process.argv[2];
if (!path) {
  console.error("usage: node examples/node.mjs <file.pdf>");
  process.exit(2);
}

const bytes = new Uint8Array(readFileSync(path));
const result = await verify(bytes);

// These two are the only failures OF THE DOCUMENT. Everything else is
// informational — see README.md's status table before treating any other
// status as red/broken.
const failed = result.status === "mismatch" || result.status === "unverified";

console.log(`status:            ${result.status}${failed ? "  (FAILED)" : ""}`);
console.log(`signatures:        ${result.signatureCount ?? 0}`);
console.log(`timestamps:        ${result.timestampCount ?? 0}`);

if (!failed && result.status !== "no-signature" && result.status !== "unsupported") {
  console.log(`time:              ${result.genTime ?? "(none)"} (${result.genTimeTrusted ? "proven" : "claimed by signer"})`);
  console.log(`signed by:         ${result.signedBy ?? "(document timestamp — no signer identity)"}`);
  console.log(`root anchored:     ${result.anchored}  (${result.rootName ?? "n/a"})`);
  console.log(`provable until:    ${result.provableUntil ?? "(no proven time to anchor to)"}`);
}

if (result.notes?.length) {
  console.log("\nnotes:");
  for (const n of result.notes) console.log(`  - ${n}`);
}

process.exit(failed ? 1 : 0);
