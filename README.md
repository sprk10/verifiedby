# verifiedby

[![npm](https://img.shields.io/npm/v/verifiedby)](https://www.npmjs.com/package/verifiedby)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

An independent, offline verifier for RFC 3161 timestamped and digitally
signed PDFs, as an npm package you can embed in your own app.

This is the exact engine that runs **[truedoc.eu](https://truedoc.eu)** —
drop a PDF into that page and it runs this same code, entirely in your
browser, with no upload. This package is that engine, published so you can
run the same check inside your own product instead of sending users to ours.

Zero dependencies. Node 20+, or any browser, Deno, or Bun with
`crypto.subtle` — which is to say, all of them.

```bash
npm install verifiedby
```

---

## What it proves

- The file is **byte-for-byte identical** to what was signed or
  timestamped. Change one byte and it fails.
- The signature over that fact is cryptographically valid, and its
  certificate chain is intact.
- When it happened — and whether that time is **proven by a timestamp
  authority** or merely **claimed by the signer's own software**. Most
  tools blur those together; this does not.
- **How long the proof lasts.** Every certificate expires, so every
  document has a date after which its validity can no longer be
  demonstrated from the file alone.

## What it does not prove

- **Who.** A document timestamp records *when*, never *who* — it carries no
  signer identity at all. An ordinary signature proves which *certificate*
  was used, which is a fact about a key, not a verified fact about a
  person. If you need identity, see [Identity is a separate
  claim](#identity-is-a-separate-claim) below.
- That the document is honest, that the sender is who they claim, or that
  its contents are correct. Confirm those the way you always would.
- Certificate revocation, which needs network access this package
  deliberately does not take — see [What this deliberately doesn't
  do](#what-this-deliberately-doesnt-do).

The full rubric — what's checked, in what order, what each verdict means,
and what would have to be true for each to be wrong — is published as
[`METHODOLOGY.md`](https://github.com/signedbyai/truedoc/blob/main/METHODOLOGY.md)
in the truedoc.eu repository, since this package runs the identical checks.

---

## Quickstart

```js
import { readFileSync } from "node:fs";
import { verify } from "verifiedby";

const bytes = new Uint8Array(readFileSync("contract.pdf"));
const result = await verify(bytes);

console.log(result.status);
// "verified" | "verified-untrusted-root" | "signed-untimed" |
// "unverified" | "mismatch" | "unsupported" | "no-signature"

if (result.status === "verified" || result.status === "verified-untrusted-root") {
  console.log("Signed/timestamped at:", result.genTime, "proven:", result.genTimeTrusted);
  console.log("Provable until:", result.provableUntil);
}
```

That's the whole embedding story: pass in bytes, get back a plain object.
No network calls, no async setup, no config required for the common case.

More runnable examples: [`examples/node.mjs`](examples/node.mjs),
[`examples/browser.html`](examples/browser.html),
[`examples/deno.mjs`](examples/deno.mjs) (Bun runs the same file unchanged).

---

## API reference

### `verify(pdfBytes, trustAnchors?)`

```ts
function verify(
  pdfBytes: Uint8Array,
  trustAnchors?: Uint8Array[] // additional DER root certs, beyond KNOWN_ROOTS
): Promise<VerifyResult>
```

Verifies every signature and timestamp embedded in a PDF and returns one
result object describing the outermost one — the signature or timestamp
covering the most of the file, i.e. the one that speaks for the document as
it currently stands. Full per-element detail is in `result.elements`
(oldest first), which matters for a PAdES-LTA file carrying more than one
timestamp.

**`result.status`** — one of:

| Status | Means | Read as |
|---|---|---|
| `verified` | Everything checks out and the root is one we pin | pass |
| `verified-untrusted-root` | Everything checks out; the root just isn't pinned | pass — confirm the authority yourself |
| `signed-untimed` | Valid signature, but nothing proves *when* | pass, weaker claim |
| `no-signature` | Nothing embedded to check | informational |
| `unsupported` | Signed in a format this engine can't parse | limit of the tool, not a finding |
| `unverified` | A signature is present but didn't check out | **fail** |
| `mismatch` | A digest doesn't match the file | **fail** |

Only `mismatch` and `unverified` are failures of the document. Everything
else is a statement about what the document contains, or about the limits
of this engine — see `METHODOLOGY.md` linked above before you build any UI
that renders these as red/green, so you don't reproduce the exact bug this
project already found and fixed (unrecognised-authority documents rendered
as if broken).

**Other result fields worth reading directly, rather than re-deriving:**
`genTime` / `genTimeTrusted` (claimed vs. proven), `provableUntil` /
`provableVia` (the date past which the file alone can no longer prove
itself, and which authority's certificate that date comes from),
`signedBy` / `signedByOrg`, `chain`, `notes` (plain-language caveats worth
surfacing to a human, e.g. "certificate revocation was not checked").

Full shape: [`src/verify-core.d.ts`](src/verify-core.d.ts).

### `extractSignatures(pdfBytes)`

Returns the raw signature dictionaries found in a PDF — byte ranges,
`/Contents` token, `/SubFilter`, claimed time — without running any
cryptographic verification. `verify()` calls this internally; it's exposed
for callers who want the raw material themselves (a signature inventory,
say, without deciding trust).

### `KNOWN_ROOTS`

The short, deliberately human-checkable list of pinned trust anchors,
pinned **by public key** (SHA-256 of the SubjectPublicKeyInfo) rather than
by certificate fingerprint, because roots get legitimately cross-signed
into multiple certificates sharing one key. Most real-world documents will
not match this list — that's `verified-untrusted-root`, and it's a pass,
not a failure.

If you operate your own timestamp authority and want its root recognised
by your embedding of this package without waiting on an upstream release,
pass its DER certificate via `verify()`'s `trustAnchors` argument rather
than forking `KNOWN_ROOTS`.

### Identity is a separate claim

```ts
function registerResolver(resolver: { name, resolve(result, pdfBytes) }): number
function resolveIdentity(result, pdfBytes): Promise<IdentityResolution[]>
```

A DocTimeStamp says *when*, never *who* — that's not a limitation of this
code, it's what the RFC 3161 format actually contains. If your application
knows something about a document (its own signer records, say), register a
resolver to attach that as a clearly separate, display-only claim. It is
never merged into `VerifyResult` itself, on purpose: cryptographic proof
and "a party's records say" are different kinds of evidence and should
never be rendered as though they were the same one.

```js
import { registerResolver, resolveIdentity, verify } from "verifiedby";

registerResolver({
  name: "your-app",
  async resolve(result, pdfBytes) {
    // look up whatever your app knows about this document
    return { name: "Jane Doe", url: "https://yourapp.example/doc/123" };
  },
});

const result = await verify(bytes);
const identity = await resolveIdentity(result, bytes); // [{ source: "your-app", name: "Jane Doe", ... }]
```

---

## What this deliberately doesn't do

- **No network requests, ever.** Verification runs entirely on the bytes
  you pass in and `crypto.subtle`. That also means certificate revocation
  is not checked — doing so needs a network call, which would break that
  guarantee. For a timestamp this matters less: the signature proves the
  certificate was in use at the stated time.
- **No trust anchor download or CA bundle.** `KNOWN_ROOTS` is a short,
  hand-verified list on purpose, not a full trust store — see above.
- **No PDF rewriting, signing, or repair.** Read-only, verification-only.

## Supported

RFC 3161 document timestamps (`/ETSI.RFC3161`), ordinary detached
signatures (`/adbe.pkcs7.detached`, `/ETSI.CAdES.detached`), CAdES-T
signature timestamps carried as unsigned attributes, Adobe
revocation-info-archival, PAdES-LTA files with multiple timestamps, RSA and
ECDSA (P-256/384/521).

Anything else returns `status: "unsupported"` — stated as a limit of this
package, never dressed up as a finding about your document.

## Reference implementation

**[truedoc.eu](https://truedoc.eu)** runs this exact engine as a
zero-dependency, single-file, offline web page — point end users at it
directly if you'd rather not build your own UI. Its
[source](https://github.com/signedbyai/truedoc) is where this engine
actually lives; this package tracks it. Its
[METHODOLOGY.md](https://github.com/signedbyai/truedoc/blob/main/METHODOLOGY.md)
is the full rubric referenced throughout this README.

## Security

Found a file that should fail and instead verifies? Please report it
privately first: **security@signedby.ai**. See
[SECURITY.md](https://github.com/signedbyai/truedoc/blob/main/SECURITY.md)
for scope and response times — the same policy covers this package, since
it's the same engine.

False rejections (a valid document reported as broken) are treated as real
bugs too, not cosmetic ones.

## Who made this

Built and operated by **SPRK10 B.V.**, the company behind
[SignedBy](https://signedby.ai). We say so plainly rather than leaving it
to be discovered — the point of this package running entirely on your own
infrastructure, with no calls back to us, is that you don't have to take
our word for what it does. Read it.

## Licence

[Apache-2.0](LICENSE). The names "verifiedby", "TrueDOC" and "SignedBy" are
trademarks of SPRK10 B.V. and are not licensed with the code (Apache-2.0
§6) — fork and republish freely, but under your own name, so a reader can
always tell whose verifier they're running.
