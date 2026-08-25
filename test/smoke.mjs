// Smoke test — runs with zero fixtures, so it works in a fresh clone or CI
// with nothing extra to fetch.
//
// This is NOT the behavioural regression suite for the verification engine
// itself: that lives in the truedoc repository's test/verify-fixtures.mjs,
// against real signed/timestamped PDFs that aren't redistributable here
// (some are real sealed documents, one is a third party's export — same
// reason as there). This package re-publishes that engine unchanged, so
// this file only checks that the package boundary — exports, and the
// no-fixture-needed code paths — is intact.
//
//   node test/smoke.mjs

import { verify, extractSignatures, KNOWN_ROOTS, registerResolver, resolveIdentity, resolvers } from "../src/verify-core.mjs";

let failed = 0;
function check(name, cond) {
  if (cond) {
    console.log(`ok   ${name}`);
  } else {
    console.log(`FAIL ${name}`);
    failed++;
  }
}

// --- exports ---------------------------------------------------------
check("exports verify", typeof verify === "function");
check("exports extractSignatures", typeof extractSignatures === "function");
check("exports registerResolver", typeof registerResolver === "function");
check("exports resolveIdentity", typeof resolveIdentity === "function");
check("exports KNOWN_ROOTS as a non-empty array", Array.isArray(KNOWN_ROOTS) && KNOWN_ROOTS.length > 0);
check("exports resolvers as an array", Array.isArray(resolvers));

// --- crypto.subtle is actually available on this runtime -------------
check("crypto.subtle is available", typeof globalThis.crypto?.subtle?.digest === "function");

// --- no-signature path (needs no fixture PDF) -------------------------
const minimalPdf = new TextEncoder().encode("%PDF-1.4\n%%EOF");
const result = await verify(minimalPdf);
check("verify() on an unsigned PDF resolves", !!result);
check("status is no-signature", result.status === "no-signature");
check("elements is an empty array", Array.isArray(result.elements) && result.elements.length === 0);
check("extractSignatures() on the same bytes finds nothing", extractSignatures(minimalPdf).length === 0);

// --- garbage input doesn't throw an unhandled exception ---------------
try {
  const garbage = new Uint8Array([1, 2, 3, 4, 5]);
  const r = await verify(garbage);
  check("verify() on garbage bytes resolves rather than throwing", !!r && typeof r.status === "string");
} catch (e) {
  check(`verify() on garbage bytes resolves rather than throwing (threw: ${e.message})`, false);
}

// --- resolver registration round-trips --------------------------------
registerResolver({
  name: "smoke-test",
  async resolve() {
    return { name: "Example" };
  },
});
const identity = await resolveIdentity(result, minimalPdf);
check(
  "a registered resolver's output comes back from resolveIdentity()",
  identity.some((r) => r.source === "smoke-test" && r.name === "Example")
);

console.log(`\n${failed === 0 ? "all checks passed" : failed + " check(s) FAILED"}`);
process.exit(failed ? 1 : 0);
