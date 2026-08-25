// truedoc.eu — independent PDF signature & timestamp verifier (core).
//
// Deliberately zero dependencies: a minimal DER walker plus WebCrypto. The
// whole point of this tool is that it keeps working when nothing else is
// around — no npm install, no CDN, no signedby.ai. Anything it needs, it
// carries.
//
// What it proves: that the PDF in your hand is byte-identical to what was
// signed or timestamped, that the signature over that fact is valid, and
// that it chains to a root you trust.
//
// What it does NOT prove: for a DocTimeStamp, WHO made the document — a
// DocTimeStamp carries no signer certificate, only a time. For an ordinary
// signature it proves which certificate signed, which is a claim about a
// key, not a verified claim about a human. Identity is a separate claim
// from a separate source — see the resolver hook at the bottom.
//
// 2026-08-14: rewritten to handle ORDINARY signed PDFs, not just RFC 3161
// DocTimeStamps. The previous version threw "not a TSTInfo timestamp" on
// anything using /adbe.pkcs7.detached or /ETSI.CAdES.detached — i.e. on
// Adobe, DocuSign, Scrive and essentially every signed PDF in the world
// that we did not produce ourselves. The UI rendered that as a RED banner,
// so a perfectly valid contract from another vendor was presented exactly
// like a tampered one. That is a false rejection, the one failure mode this
// tool exists to avoid, and it also meant an "independent verifier" that in
// practice only verified our own output.

const OID = {
  signedData: "1.2.840.113549.1.7.2",
  data: "1.2.840.113549.1.7.1",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  messageDigest: "1.2.840.113549.1.9.4",
  contentType: "1.2.840.113549.1.9.3",
  signingTime: "1.2.840.113549.1.9.5",
  // CAdES-T: a timestamp over the signature value, carried as an UNSIGNED
  // attribute. This is how most e-signature vendors prove when a signature
  // happened — it is not a document-level DocTimeStamp and must not be
  // conflated with one.
  signatureTimeStampToken: "1.2.840.113549.1.9.16.2.14",
  // Adobe's pre-DSS way of carrying revocation material, inside the SIGNED
  // attributes. Older than /DSS but still widely emitted, and still what
  // Acrobat's legacy LTV path reads.
  adbeRevocationInfoArchival: "1.2.840.113583.1.1.8",
  rsaEncryption: "1.2.840.113549.1.1.1",
  ecPublicKey: "1.2.840.10045.2.1",
};

const DIGEST_BY_OID = {
  "1.3.14.3.2.26": "SHA-1",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
};

// signatureAlgorithm OIDs -> the digest WebCrypto should use with RSA.
const RSA_SIG_BY_OID = {
  "1.2.840.113549.1.1.5": "SHA-1",
  "1.2.840.113549.1.1.11": "SHA-256",
  "1.2.840.113549.1.1.12": "SHA-384",
  "1.2.840.113549.1.1.13": "SHA-512",
  // rsaEncryption appears as the SignerInfo signatureAlgorithm in plenty of
  // real CMS; the digest then comes from SignerInfo.digestAlgorithm.
  "1.2.840.113549.1.1.1": null,
};

// ECDSA equivalents. Needed because not every TSA signs with RSA: EuroTSA's
// own key is EC P-384 (GCP KMS EC_SIGN_P384_SHA384), and an RSA-only verifier
// reports those perfectly good timestamps as unverified — which reads to a
// user as "possibly forged". That failure mode is worse than saying nothing.
const ECDSA_SIG_BY_OID = {
  "1.2.840.10045.4.1": "SHA-1",
  "1.2.840.10045.4.3.1": "SHA-224",
  "1.2.840.10045.4.3.2": "SHA-256",
  "1.2.840.10045.4.3.3": "SHA-384",
  "1.2.840.10045.4.3.4": "SHA-512",
};

const CURVE_BY_OID = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
};

// Byte width of one ECDSA coordinate per curve — needed to left-pad r and s
// when converting a DER signature to the raw form WebCrypto expects.
const COORD_BYTES = { "P-256": 32, "P-384": 48, "P-521": 66 };

// How each /SubFilter carries its proof. The distinction that matters:
//   doctimestamp — eContent IS a TSTInfo; its imprint covers the document.
//   detached     — no eContent; the messageDigest ATTRIBUTE covers the
//                  document directly. This is the ordinary signed-PDF case.
const SUBFILTERS = {
  "ETSI.RFC3161": { kind: "doctimestamp", label: "document timestamp" },
  "adbe.pkcs7.detached": { kind: "detached", label: "digital signature" },
  "ETSI.CAdES.detached": { kind: "detached", label: "digital signature (CAdES)" },
};

/* ------------------------------------------------------------------ DER */

function tlv(buf, pos) {
  const first = buf[pos];
  let p = pos + 1;
  // Multi-byte tags are legal but never appear in these structures; treating
  // one as a parse error is safer than guessing at its meaning.
  if ((first & 0x1f) === 0x1f) throw new Error("multi-byte DER tag");
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("unsupported DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[p++];
  }
  return { tag: first, start: pos, vStart: p, vEnd: p + len, end: p + len };
}

function children(buf, node) {
  const out = [];
  let p = node.vStart;
  while (p < node.vEnd) {
    const c = tlv(buf, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

function oidOf(buf, node) {
  const b = buf.subarray(node.vStart, node.vEnd);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}

// DER GeneralizedTime, always UTC in TSTInfo.
function generalizedTime(buf, node) {
  const s = new TextDecoder().decode(buf.subarray(node.vStart, node.vEnd));
  const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/);
  if (!m) throw new Error("unparseable GeneralizedTime: " + s);
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

function utcOrGenTime(buf, node) {
  const s = new TextDecoder().decode(buf.subarray(node.vStart, node.vEnd));
  if (node.tag === 0x17) {
    const m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) throw new Error("unparseable UTCTime");
    const yy = +m[1];
    return new Date(Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }
  return generalizedTime(buf, node);
}

const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");

/* ------------------------------------------------------- PDF extraction */

// Parse a PDF date string: D:YYYYMMDDHHmmSS with an optional offset.
function pdfDate(s) {
  const m = /^D?:?(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?(?:([+-Z])(\d{2})'?(\d{2})'?)?/.exec(s || "");
  if (!m) return null;
  let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4] || 0, +m[5] || 0, +m[6] || 0);
  if (m[7] === "+" || m[7] === "-") {
    const off = ((+m[8]) * 60 + (+m[9] || 0)) * 60000;
    t += m[7] === "+" ? -off : off;
  }
  return new Date(t);
}

/**
 * Pull EVERY signature dictionary's ByteRange and /Contents token out of the
 * raw PDF, in file order. Done by scanning rather than by parsing the object
 * graph: the byte offsets are what matter cryptographically, and a full PDF
 * parser would be far more code and far more to get wrong.
 *
 * 2026-08-14: was `extractTimestamp`, and used `.exec()` — one match only. On
 * an archive-timestamped (PAdES-LTA) file that silently read the FIRST
 * signature and ignored the archive timestamp entirely, reporting the older
 * time and the wrong authority. Now returns all of them.
 */
export function extractSignatures(bytes) {
  const text = new TextDecoder("latin1").decode(bytes);
  const out = [];
  const re = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;

  for (let m; (m = re.exec(text)) !== null; ) {
    const [a, b, c, d] = m.slice(1, 5).map(Number);
    if (!(a >= 0 && b >= 0 && c >= a + b && c + d <= bytes.length)) continue;

    // /Contents is the hex string sitting in the gap the ByteRange skips.
    const gap = text.slice(a + b, c);
    const lt = gap.indexOf("<"), gt = gap.lastIndexOf(">");
    if (lt < 0 || gt < 0) continue;
    const rawHex = gap.slice(lt + 1, gt).replace(/[^0-9a-fA-F]/g, "");
    if (rawHex.length < 4) continue;
    const token = new Uint8Array(rawHex.length >> 1);
    for (let i = 0; i < token.length; i++) token[i] = parseInt(rawHex.substr(i * 2, 2), 16);

    const signed = new Uint8Array(b + d);
    signed.set(bytes.subarray(a, a + b), 0);
    signed.set(bytes.subarray(c, c + d), b);

    // Read the surrounding signature dictionary by bracketing it: scan back to
    // the nearest "<<" and forward to the nearest ">>". Writers put the dict
    // keys on EITHER side of /ByteRange — SignedBy's own seals lead with
    // /Type and /SubFilter, while Scrive/Contractbook write /Contents first
    // and the keys after it — so a one-sided window silently reads nothing.
    // The huge /Contents hex blob contains no angle brackets, so scanning
    // straight through it is safe.
    let dStart = text.lastIndexOf("<<", m.index);
    if (dStart < 0 || m.index - dStart > 4_000_000) dStart = Math.max(0, m.index - 2000);
    let dEnd = text.indexOf(">>", m.index);
    if (dEnd < 0) dEnd = Math.min(text.length, m.index + 2000);
    const win = text.slice(dStart, dEnd + 2);
    const pick = (rx) => { const q = rx.exec(win); return q ? q[1] : null; };

    out.push({
      byteRange: [a, b, c, d],
      signed,
      token,
      subFilter: pick(/\/SubFilter\s*\/([A-Za-z0-9.]+)/g),
      dictType: pick(/\/Type\s*\/(Sig|DocTimeStamp)\b/g),
      claimedTime: pdfDate(pick(/\/M\s*\(([^)]*)\)/g)),
      reason: pick(/\/Reason\s*\(([^)]*)\)/g),
      coversWholeFile: a === 0 && c + d === bytes.length,
      trailingBytes: bytes.length - (c + d),
      trailing: text.slice(c + d),
    });
  }

  // Outermost last: the signature covering the most of the file is the newest.
  out.sort((x, y) => (x.byteRange[2] + x.byteRange[3]) - (y.byteRange[2] + y.byteRange[3]));
  return out;
}

/**
 * Classify the bytes after a signed range.
 *
 * Bytes after the signed range are NORMAL and must not be reported as
 * tampering. Validation material (/DSS, OCSP, CRLs) and any LATER signature
 * are appended as incremental updates after signing — by construction the
 * earlier signature cannot cover them.
 *
 * 2026-08-14 fix: the old heuristic treated "/Contents" as evidence of
 * appended PAGE content. Every signature dictionary contains /Contents by
 * definition, so any archive-timestamped or counter-signed file tripped the
 * scary branch and was told its own proof "appears to contain page content" —
 * a stronger document reported as more suspicious than a weaker one.
 *
 * Signature updates also legitimately touch /Annots and the page object — a
 * signature field IS an annotation on a page — so page markers alone cannot
 * mean tampering. Only page markers with NO signature markers do.
 *
 * Note that ABSENCE of markers is the benign case, not a suspicious one:
 * every SignedBy seal appends its /DSS inside a COMPRESSED object stream, so
 * the literal string "/DSS" does not appear in the trailing bytes at all and
 * cannot be grepped for. Trailing bytes with no page markers are reported as
 * expected appended data, because that is what they almost always are.
 */
function classifyTrailing(trailing, trailingBytes) {
  if (trailingBytes <= 0) return { kind: "none" };
  const sig = /\/ByteRange|\/DSS\b|\/VRI\b|\/DocTimeStamp\b|\/Adobe\.PPKLite/.test(trailing);
  const page = /\/Type\s*\/Page[^s]|\/MediaBox|\/Annots/.test(trailing);
  if (sig) return { kind: "signature-update" };
  if (page) return { kind: "page-content" };
  return { kind: "appended-data" };
}

/* ---------------------------------------------------------- CMS parsing */

// Parse CMS SignedData WITHOUT assuming what it encapsulates. The old version
// hard-failed unless eContentType was TSTInfo, which is what made every
// ordinary signed PDF throw.
function parseCms(token) {
  const root = tlv(token, 0);
  const [ctOid, wrapper] = children(token, root);
  if (oidOf(token, ctOid) !== OID.signedData) throw new Error("not CMS SignedData");
  const sd = children(token, wrapper)[0];
  const kids = children(token, sd);

  // version, digestAlgorithms, encapContentInfo, [0] certs?, [1] crls?, signerInfos
  const eci = kids[2];
  const eciKids = children(token, eci);
  const eContentType = oidOf(token, eciKids[0]);
  // Detached signatures carry no eContent at all — legal, and the norm.
  let eContent = null;
  if (eciKids[1]) {
    const oct = children(token, eciKids[1])[0];
    if (oct) eContent = token.subarray(oct.vStart, oct.vEnd);
  }

  const certs = [];
  let signerInfos = null;
  for (const k of kids.slice(3)) {
    if (k.tag === 0xa0) for (const c of children(token, k)) certs.push(c);
    else if (k.tag === 0x31) signerInfos = k;
  }
  if (!signerInfos) throw new Error("no signerInfos");

  return { eContentType, eContent, certs, signer: children(token, signerInfos)[0] };
}

// Pull the pieces of a SignerInfo we need, tolerating the optional fields.
function parseSignerInfo(buf, signer) {
  const sk = children(buf, signer);
  let signedAttrs = null, unsignedAttrs = null, digAlgNode = null, sigAlgNode = null, sigNode = null;
  for (let i = 2; i < sk.length; i++) {
    const n = sk[i];
    if (n.tag === 0xa0 && !signedAttrs) signedAttrs = n;
    else if (n.tag === 0xa1) unsignedAttrs = n;
    else if (n.tag === 0x30 && !digAlgNode) digAlgNode = n;
    else if (n.tag === 0x30) sigAlgNode = n;
    else if (n.tag === 0x04) sigNode = n;
  }
  if (!digAlgNode) digAlgNode = sk[2];
  return { signedAttrs, unsignedAttrs, digAlgNode, sigAlgNode, sigNode };
}

// Find an attribute's value node inside a SET OF Attribute.
function findAttr(buf, attrsNode, wantOid) {
  if (!attrsNode) return null;
  for (const attr of children(buf, attrsNode)) {
    const [aOid, aVal] = children(buf, attr);
    if (oidOf(buf, aOid) === wantOid) return children(buf, aVal)[0] ?? null;
  }
  return null;
}

function parseTstInfo(eContent) {
  const root = tlv(eContent, 0);
  const k = children(eContent, root);
  const policy = oidOf(eContent, k[1]);
  const mi = children(eContent, k[2]);
  const hashAlg = DIGEST_BY_OID[oidOf(eContent, children(eContent, mi[0])[0])];
  const imprintNode = mi[1];
  const imprint = eContent.subarray(imprintNode.vStart, imprintNode.vEnd);
  // serialNumber is k[3]; genTime k[4]
  const genTime = generalizedTime(eContent, k[4]);
  return { policy, hashAlg, imprint, genTime };
}

function parseCert(buf, node) {
  const [tbs, sigAlg, sigVal] = children(buf, node);
  const t = children(buf, tbs);
  let i = 0;
  if (t[0].tag === 0xa0) i = 1; // explicit version
  const serial = buf.subarray(t[i].vStart, t[i].vEnd);
  const issuer = buf.subarray(t[i + 2].start, t[i + 2].end);
  const validity = children(buf, t[i + 3]);
  const subject = buf.subarray(t[i + 4].start, t[i + 4].end);
  const spki = buf.subarray(t[i + 5].start, t[i + 5].end);
  const sigBits = buf.subarray(sigVal.vStart + 1, sigVal.vEnd); // drop unused-bits byte
  return {
    der: buf.subarray(node.start, node.end),
    tbs: buf.subarray(tbs.start, tbs.end),
    serial, issuer, subject, spki,
    notBefore: utcOrGenTime(buf, validity[0]),
    notAfter: utcOrGenTime(buf, validity[1]),
    sigAlgOid: oidOf(buf, children(buf, sigAlg)[0]),
    signature: sigBits,
    cn: rdnValue(buf, t[i + 4], "2.5.4.3") ?? "(unnamed)",
    org: rdnValue(buf, t[i + 4], "2.5.4.10"),
  };
}

// Best-effort RDN lookup for display only — never used in a trust decision.
function rdnValue(buf, nameNode, wantOid) {
  try {
    for (const rdn of children(buf, nameNode)) {
      for (const atv of children(buf, rdn)) {
        const [oid, val] = children(buf, atv);
        if (oidOf(buf, oid) === wantOid) {
          return new TextDecoder().decode(buf.subarray(val.vStart, val.vEnd));
        }
      }
    }
  } catch { /* display only */ }
  return null;
}

// Read the key type straight out of the SubjectPublicKeyInfo rather than
// guessing it from the signature algorithm — the two can disagree, and the
// key is what actually has to import.
function spkiInfo(spki) {
  const algId = children(spki, tlv(spki, 0))[0];
  const algKids = children(spki, algId);
  const algOid = oidOf(spki, algKids[0]);
  if (algOid === OID.ecPublicKey) {
    // For named curves the AlgorithmIdentifier parameter is the curve OID.
    const curveOid = algKids[1] && algKids[1].tag === 0x06 ? oidOf(spki, algKids[1]) : null;
    return { kind: "EC", curve: CURVE_BY_OID[curveOid] ?? null, curveOid };
  }
  if (algOid === OID.rsaEncryption) return { kind: "RSA", algOid };
  return { kind: "unknown", algOid };
}

// X.509 and CMS carry an ECDSA signature as a DER SEQUENCE { r, s }, but
// WebCrypto wants the raw fixed-width concatenation r||s. Getting this
// wrong doesn't error — verification just silently returns false — so it is
// worth being explicit about both directions of padding: DER INTEGERs are
// signed, so r or s may carry a leading 0x00 that must come off, and either
// may be shorter than the coordinate width and must be left-padded.
function derEcdsaToRaw(der, coordBytes) {
  const [rNode, sNode] = children(der, tlv(der, 0));
  const out = new Uint8Array(coordBytes * 2);
  const place = (node, offset) => {
    let b = der.subarray(node.vStart, node.vEnd);
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.subarray(i);
    if (b.length > coordBytes) throw new Error("ECDSA coordinate wider than curve");
    out.set(b, offset + coordBytes - b.length);
  };
  place(rNode, 0);
  place(sNode, coordBytes);
  return out;
}

async function verifySignature(spki, sigAlgOid, digestName, data, signature) {
  const info = spkiInfo(spki);

  if (info.kind === "EC") {
    const hash = ECDSA_SIG_BY_OID[sigAlgOid] ?? digestName;
    if (!hash) throw new Error("unsupported ECDSA signature algorithm " + sigAlgOid);
    if (!info.curve) throw new Error("unsupported EC curve " + info.curveOid);
    const key = await crypto.subtle.importKey(
      "spki", spki, { name: "ECDSA", namedCurve: info.curve }, false, ["verify"]
    );
    const raw = derEcdsaToRaw(signature, COORD_BYTES[info.curve]);
    return crypto.subtle.verify({ name: "ECDSA", hash }, key, raw, data);
  }

  if (info.kind === "RSA") {
    const hash = RSA_SIG_BY_OID[sigAlgOid] ?? digestName;
    if (!hash) throw new Error("unsupported RSA signature algorithm " + sigAlgOid);
    const key = await crypto.subtle.importKey(
      "spki", spki, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]
    );
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
  }

  throw new Error("unsupported public key algorithm " + info.algOid);
}

async function digest(name, data) {
  return new Uint8Array(await crypto.subtle.digest(name, data));
}

async function sha256Hex(bytes) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/* -------------------------------------------------------------- trust */

// Trust has to start somewhere, and pretending otherwise would be dishonest.
// Rather than bundle megabytes of root certificates, this pins the roots we
// expect, so the list stays short enough for a person to actually check.
//
// Pinned by PUBLIC KEY (SubjectPublicKeyInfo), not by certificate. A root is
// routinely cross-signed, producing several certificates with the same name
// and the same key but different bytes — and therefore different certificate
// fingerprints. Sectigo Public Time Stamping Root R46 is exactly this case:
// the self-signed copy in Apple's trust store hashes to 4941b001..., while the
// copy embedded in a SignedBy PDF (cross-signed by USERTrust RSA
// Certification Authority) hashes to b53ac15c.... Same key, different papers.
// Pinning the certificate would have rejected one of them for no good reason;
// the key is what verifies signatures, so the key is what we pin.
//
// VERIFIED 2026-08-14: the SPKI hash below was read back out of Apple's
// System Roots keychain on a machine with no connection to this project —
//   security find-certificate -p -c "Sectigo Public Time Stamping Root R46" \
//     /System/Library/Keychains/SystemRootCertificates.keychain \
//     | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER \
//     | openssl dgst -sha256
// — and matched. Re-run that if you ever doubt this constant. Do not trust it
// because it is written here.
//
// NOTE ON SCOPE: this list is deliberately tiny, so most third-party
// documents will report "authority not recognised". That is the honest
// answer and NOT a failure — it means the proof is internally sound and the
// reader should confirm the authority themselves. It must never be rendered
// as though the document were bad.
export const KNOWN_ROOTS = [
  {
    cn: "Sectigo Public Time Stamping Root R46",
    spkiSha256: "a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795",
    note: "Also shipped as a trusted root by Apple, Microsoft and Adobe.",
  },

  // EuroTSA (EC P-384, self-signed, GCP KMS backed). Deliberately NOT filled
  // in from anything this project produced — pinning a value taken from our
  // own service would be circular, exactly the trap avoided for Sectigo
  // above. Read the real value off the live service and paste it here:
  //
  //   curl -s https://eurotsa.eu/tsr/certchain \
  //     | openssl x509 -noout -pubkey \
  //     | openssl pkey -pubin -outform DER \
  //     | openssl dgst -sha256
  //
  // Note that a self-signed root is a weaker claim than Sectigo's: nobody
  // else vouches for it. Until it is pinned, EuroTSA-stamped documents
  // report "verified-untrusted-root", which is the honest answer — the
  // timestamp is cryptographically sound, the authority is just not one a
  // third party has independently blessed. Only add it if you intend this
  // tool to vouch for our own TSA, and say so plainly in the UI if you do.
  //
  // {
  //   cn: "EuroTSA Root",
  //   spkiSha256: "<paste the sha256 from the command above>",
  //   note: "Self-signed EU timestamp authority operated by SPRK10 B.V.",
  // },
];

/* ------------------------------------------------- per-element verify */

// Build the certificate chain upward from the signer, as far as the
// embedded certificates allow.
function buildChain(certs, signerCert) {
  const chain = [signerCert];
  let cur = signerCert;
  for (let hop = 0; hop < 8; hop++) {
    if (eq(cur.issuer, cur.subject)) break; // self-issued: top of embedded chain
    const next = certs.find((c) => eq(c.subject, cur.issuer) && c !== cur);
    if (!next) break;
    chain.push(next);
    cur = next;
  }
  return chain;
}

async function checkChain(chain, notes) {
  let ok = chain.length > 0;
  for (let i = 0; i < chain.length - 1; i++) {
    try {
      const good = await verifySignature(
        chain[i + 1].spki, chain[i].sigAlgOid, null, chain[i].tbs, chain[i].signature
      );
      if (!good) { ok = false; notes.push(`Certificate link ${chain[i].cn} -> ${chain[i + 1].cn} failed.`); }
    } catch (e) { ok = false; notes.push("Chain check failed: " + e.message); }
  }
  return ok;
}

async function anchorOf(chain, trustAnchors) {
  const top = chain[chain.length - 1];
  const certFp = await sha256Hex(top.der);
  const keyFp = await sha256Hex(top.spki);
  const pinned = KNOWN_ROOTS.find((r) => r.spkiSha256 === keyFp);
  const anchors = trustAnchors.map((d) => parseCert(d, tlv(d, 0)));
  const anchored = !!pinned || anchors.some((a) => eq(a.subject, top.subject) || eq(a.subject, top.issuer));
  // A chain that stops at a certificate which is NOT self-issued has simply
  // run out of embedded certificates — the issuer was never included. Saying
  // "root: <signer>" there would be actively misleading, so name the gap.
  const complete = eq(top.issuer, top.subject);
  return {
    anchored,
    rootName: pinned ? pinned.cn : top.cn,
    chainComplete: complete,
    certFp, keyFp,
  };
}

// Verify a CMS SignerInfo's signature over its signed attributes, plus that
// those attributes commit to the expected bytes. `expectedOver` is what the
// messageDigest attribute must hash: eContent for encapsulated content, or
// the signed document bytes for a detached signature.
async function verifyCmsSigner(tok, signer, signerCert, expectedOver, notes) {
  const { signedAttrs, sigAlgNode, sigNode, digAlgNode } = parseSignerInfo(tok, signer);
  const signerDigest = DIGEST_BY_OID[oidOf(tok, children(tok, digAlgNode)[0])];
  let signatureValid = false, attrsCommit = false;

  if (!signedAttrs || !sigNode) {
    notes.push("Signature has no signed attributes — cannot verify authenticity.");
    return { signatureValid, attrsCommit, signerDigest, signedAttrs, sigNode };
  }

  // SignedAttrs is DER-encoded as a SET (0x31) for signing, not the
  // [0] IMPLICIT tag it carries inside SignerInfo.
  const attrBytes = tok.slice(signedAttrs.start, signedAttrs.end);
  attrBytes[0] = 0x31;
  const sig = tok.subarray(sigNode.vStart, sigNode.vEnd);
  const sigOid = sigAlgNode ? oidOf(tok, children(tok, sigAlgNode)[0]) : OID.rsaEncryption;
  try {
    signatureValid = await verifySignature(signerCert.spki, sigOid, signerDigest, attrBytes, sig);
  } catch (e) { notes.push("Signature check failed: " + e.message); }

  const want = await digest(signerDigest, expectedOver);
  const mdNode = findAttr(tok, signedAttrs, OID.messageDigest);
  if (mdNode) attrsCommit = eq(tok.subarray(mdNode.vStart, mdNode.vEnd), want);
  else notes.push("No messageDigest attribute present.");

  return { signatureValid, attrsCommit, signerDigest, signedAttrs, sigNode };
}

// A CAdES-T signature timestamp: an RFC 3161 token over the SIGNATURE VALUE,
// carried as an unsigned attribute. This is how most e-signature vendors
// prove *when* a signature was made. It is NOT a document timestamp — it
// covers the signature bytes, not the file — and the UI must not blur that.
async function verifySignatureTimestamp(tok, unsignedAttrs, sigNode, trustAnchors) {
  const node = findAttr(tok, unsignedAttrs, OID.signatureTimeStampToken);
  if (!node || !sigNode) return null;
  const notes = [];
  try {
    const inner = tok.subarray(node.start, node.end);
    const { eContentType, eContent, certs: certNodes, signer } = parseCms(inner);
    if (eContentType !== OID.tstInfo || !eContent) return null;
    const tst = parseTstInfo(eContent);
    const certs = certNodes.map((n) => parseCert(inner, n));
    if (!certs.length) return null;
    const signerCert = certs[0];

    // The timestamp's imprint must cover the signature value it protects.
    const sigValue = tok.subarray(sigNode.vStart, sigNode.vEnd);
    const computed = await digest(tst.hashAlg, sigValue);
    const coversSignature = eq(computed, tst.imprint);
    if (!coversSignature) notes.push("The signature timestamp does not cover this signature's value.");

    const { signatureValid, attrsCommit } = await verifyCmsSigner(inner, signer, signerCert, eContent, notes);
    const chain = buildChain(certs, signerCert);
    const chainValid = await checkChain(chain, notes);
    const { anchored, rootName, keyFp } = await anchorOf(chain, trustAnchors);

    return {
      authority: signerCert.cn,
      org: signerCert.org,
      genTime: tst.genTime,
      policy: tst.policy,
      coversSignature,
      signatureValid, attrsCommit, chainValid, anchored,
      rootName, rootKeyFingerprint: keyFp,
      notAfter: signerCert.notAfter,
      chain: chain.map((c) => ({ cn: c.cn, notAfter: c.notAfter })),
      valid: coversSignature && signatureValid && attrsCommit && chainValid,
      notes,
    };
  } catch (e) {
    return { error: e.message, valid: false, notes };
  }
}

// Adobe's legacy revocation container, inside the SIGNED attributes.
function readAdobeRevocation(tok, signedAttrs) {
  const node = findAttr(tok, signedAttrs, OID.adbeRevocationInfoArchival);
  if (!node) return null;
  let crls = 0, ocsps = 0;
  try {
    for (const c of children(tok, node)) {
      const n = children(tok, c).length;
      if (c.tag === 0xa0) crls += n;
      else if (c.tag === 0xa1) ocsps += n;
    }
  } catch { /* counts are informational only */ }
  return { crls, ocsps, source: "Adobe revocation-info-archival (signed attribute)" };
}

/** Verify ONE signature dictionary. */
async function verifyElement(el, trustAnchors) {
  const notes = [];
  const profile = SUBFILTERS[el.subFilter] ?? null;

  if (!profile) {
    return {
      kind: "unsupported",
      subFilter: el.subFilter,
      byteRange: el.byteRange,
      supported: false,
      notes: [
        `This signature uses /SubFilter ${el.subFilter || "(none)"}, which this page does not parse. ` +
        "That is a limit of this tool, not a defect in the document.",
      ],
    };
  }

  const isDocTs = profile.kind === "doctimestamp";
  const { eContentType, eContent, certs: certNodes, signer } = parseCms(el.token);
  const certs = certNodes.map((n) => parseCert(el.token, n));
  if (!certs.length) throw new Error("no certificates in signature");
  const signerCert = certs[0];
  const { unsignedAttrs } = parseSignerInfo(el.token, signer);

  let documentMatches = null, hashAlg = null, imprintHex = null, computedHex = null;
  let time = null, tstPolicy = null;

  if (isDocTs) {
    if (eContentType !== OID.tstInfo || !eContent) throw new Error("DocTimeStamp without TSTInfo content");
    const tst = parseTstInfo(eContent);
    const computed = await digest(tst.hashAlg, el.signed);
    documentMatches = eq(computed, tst.imprint);
    hashAlg = tst.hashAlg;
    imprintHex = hex(tst.imprint);
    computedHex = hex(computed);
    tstPolicy = tst.policy;
    time = { value: tst.genTime, trusted: true, source: "timestamp authority" };
  }

  const expectedOver = isDocTs ? eContent : el.signed;
  const r = await verifyCmsSigner(el.token, signer, signerCert, expectedOver, notes);

  if (!isDocTs) {
    // For a detached signature, "does the digest match the file" IS attrsCommit.
    documentMatches = r.attrsCommit;
    hashAlg = r.signerDigest;
    computedHex = hex(await digest(r.signerDigest, el.signed));
    const mdNode = findAttr(el.token, r.signedAttrs, OID.messageDigest);
    imprintHex = mdNode ? hex(el.token.subarray(mdNode.vStart, mdNode.vEnd)) : null;

    const stNode = findAttr(el.token, r.signedAttrs, OID.signingTime);
    let claimed = el.claimedTime;
    if (stNode) { try { claimed = utcOrGenTime(el.token, stNode); } catch { /* keep /M */ } }
    time = { value: claimed, trusted: false, source: "claimed by the signer" };
  }

  const chain = buildChain(certs, signerCert);
  const chainValid = await checkChain(chain, notes);
  const { anchored, rootName, chainComplete, certFp, keyFp } = await anchorOf(chain, trustAnchors);
  if (!chainComplete) {
    notes.push(
      "The issuer certificate is not embedded in this file, so the chain stops at the signing " +
      "certificate and cannot be followed to a root. Many signers rely on the reader already " +
      "holding the issuer; it is not by itself a fault in the document."
    );
  }

  const sigTs = !isDocTs
    ? await verifySignatureTimestamp(el.token, unsignedAttrs, r.sigNode, trustAnchors)
    : null;
  if (sigTs && sigTs.valid) {
    // A valid signature timestamp upgrades the time from claimed to proven.
    time = { value: sigTs.genTime, trusted: true, source: `timestamp authority (${sigTs.authority})` };
  } else if (sigTs && !sigTs.valid) {
    notes.push("A signature timestamp is present but did not verify.");
  }

  const revocation = r.signedAttrs ? readAdobeRevocation(el.token, r.signedAttrs) : null;

  const refTime = time?.value ?? new Date();
  const withinValidity = refTime >= signerCert.notBefore && refTime <= signerCert.notAfter;
  if (!withinValidity) {
    notes.push(time?.trusted
      ? "The proven time falls outside the signing certificate's validity window."
      : "The claimed time falls outside the signing certificate's validity window — but that time is only a claim.");
  }

  const trailing = classifyTrailing(el.trailing, el.trailingBytes);
  if (trailing.kind === "signature-update") {
    notes.push(
      `${el.trailingBytes} bytes follow this signed range and contain a further signature or ` +
      "validation data. That is expected: anything added after signing cannot be covered by the " +
      "signature it supports."
    );
  } else if (trailing.kind === "page-content") {
    notes.push(
      `${el.trailingBytes} bytes follow this signed range and appear to contain page content, with no ` +
      "sign of a further signature. Anything in that region is not covered and deserves caution."
    );
  } else if (trailing.kind === "appended-data") {
    notes.push(
      `${el.trailingBytes} bytes follow this signed range, with no sign of added page content. This is ` +
      "expected: validation material is appended after signing and cannot be covered by the signature " +
      "it supports."
    );
  }

  const authentic = r.signatureValid && r.attrsCommit && chainValid && withinValidity;

  return {
    kind: isDocTs ? "doctimestamp" : "signature",
    label: profile.label,
    subFilter: el.subFilter,
    supported: true,
    byteRange: el.byteRange,
    coversWholeFile: el.coversWholeFile,
    trailingBytes: el.trailingBytes,
    trailingKind: trailing.kind,
    documentMatches,
    signatureValid: r.signatureValid,
    attrsCommit: r.attrsCommit,
    chainValid, anchored, chainComplete, withinValidity, authentic,
    time,
    policy: tstPolicy,
    hashAlg, imprint: imprintHex, computed: computedHex,
    authority: signerCert.cn,
    authorityOrg: signerCert.org,
    signerNotAfter: signerCert.notAfter,
    reason: el.reason,
    rootName, rootFingerprint: certFp, rootKeyFingerprint: keyFp,
    chain: chain.map((c) => ({ cn: c.cn, notBefore: c.notBefore, notAfter: c.notAfter })),
    signatureTimestamp: sigTs,
    revocation,
    notes,
  };
}

/* -------------------------------------------------------------- verify */

/**
 * @param {Uint8Array} pdfBytes
 * @param {Uint8Array[]} trustAnchors  DER certificates treated as roots
 */
export async function verify(pdfBytes, trustAnchors = []) {
  const notes = [];
  const found = extractSignatures(pdfBytes);

  if (!found.length) {
    return {
      status: "no-signature",
      elements: [],
      notes: ["This PDF contains no embedded signature or timestamp, so there is nothing here to check."],
    };
  }

  const elements = [];
  for (const el of found) {
    try {
      elements.push(await verifyElement(el, trustAnchors));
    } catch (e) {
      elements.push({
        kind: "unreadable", supported: false, subFilter: el.subFilter,
        byteRange: el.byteRange,
        notes: [`This signature could not be parsed: ${e.message}`],
      });
    }
  }

  const usable = elements.filter((e) => e.supported);
  if (!usable.length) {
    return {
      status: "unsupported",
      elements,
      notes: [
        "This PDF is signed, but in a format this page cannot read. That is a limit of this tool, " +
        "not a finding about the document — Adobe Acrobat's own signature panel will read it.",
      ],
    };
  }

  // The outermost element covers the most of the file, so it speaks for the
  // document as it stands now.
  const outer = usable[usable.length - 1];
  const timestamps = usable.filter((e) => e.kind === "doctimestamp");
  const trustedTimes = usable.filter((e) => e.time?.trusted);

  const anyMismatch = usable.some((e) => e.documentMatches === false);
  const allAuthentic = usable.every((e) => e.authentic);
  const allAnchored = usable.every((e) => e.anchored);

  // How long can any embedded proof still be demonstrated? For each element
  // carrying a TRUSTED time, that is the expiry of the certificate that
  // signed that time. A signer certificate expiring sooner does NOT shorten
  // it, because the timestamp is what proves the signature predated its own
  // expiry. This is the honest answer to "and then what?" — and it is finite
  // for every document this tool has yet been shown.
  let provableUntil = null, provableVia = null;
  for (const e of trustedTimes) {
    const exp = e.kind === "doctimestamp" ? e.signerNotAfter : e.signatureTimestamp?.notAfter;
    if (exp && (!provableUntil || exp > provableUntil)) {
      provableUntil = exp;
      provableVia = e.kind === "doctimestamp" ? e.authority : e.signatureTimestamp?.authority;
    }
  }

  if (usable.length > 1) {
    notes.push(`${usable.length} signatures or timestamps are present; each is listed below, oldest first.`);
  }
  if (!timestamps.length && trustedTimes.length) {
    notes.push(
      "The signature here is timestamped, but there is no document-level timestamp covering the file " +
      "as a whole."
    );
  }
  if (!trustedTimes.length) {
    notes.push(
      "No trusted time source is present. Any date shown is claimed by the signer's own software and " +
      "is not independently proven."
    );
  }
  if (!allAnchored) {
    notes.push(
      "At least one authority here is not one this page recognises. That does not make it fake — this " +
      "tool pins only a short list of roots on purpose. Confirm the authority yourself."
    );
  }
  notes.push(
    "Certificate revocation was not checked; that would require network access. For a timestamp this " +
    "matters less, because the signature proves the certificate was in use at the stated time."
  );

  let status;
  if (anyMismatch) status = "mismatch";
  else if (!allAuthentic) status = "unverified";
  else if (!trustedTimes.length) status = "signed-untimed";
  else if (!allAnchored) status = "verified-untrusted-root";
  else status = "verified";

  return {
    status,
    elements,
    documentMatches: !anyMismatch,
    hasDocumentTimestamp: timestamps.length > 0,
    signatureCount: usable.filter((e) => e.kind === "signature").length,
    timestampCount: timestamps.length,
    genTime: outer.time?.value ?? null,
    genTimeTrusted: !!outer.time?.trusted,
    authority: outer.kind === "doctimestamp"
      ? outer.authority
      : (outer.signatureTimestamp?.authority ?? outer.authority),
    signedBy: outer.kind === "signature" ? outer.authority : null,
    signedByOrg: outer.kind === "signature" ? outer.authorityOrg : null,
    provableUntil, provableVia,
    anchored: allAnchored,
    chainComplete: outer.chainComplete !== false,
    rootName: outer.rootName,
    rootFingerprint: outer.rootFingerprint,
    rootKeyFingerprint: outer.rootKeyFingerprint,
    chain: outer.chain,
    hashAlg: outer.hashAlg,
    imprint: outer.imprint,
    computed: outer.computed,
    byteRange: outer.byteRange,
    coversWholeFile: outer.coversWholeFile,
    notes,
  };
}

/* ------------------------------------------------------ identity hook */

// A DocTimeStamp says WHEN, never WHO. Identity has to come from somewhere
// that knows about this document, which is by definition a party you choose
// to trust — so it is deliberately not built in, and never merged into the
// cryptographic result above.
//
// A resolver takes the verification result and returns display-only claims:
//   { name, url, claims: [{ label, value }] }
//
// Register your own:
//   registerResolver({
//     name: "signedby.ai",
//     async resolve(result, pdfBytes) { ... }
//   });
export const resolvers = [];
export function registerResolver(r) {
  if (!r || typeof r.resolve !== "function") throw new Error("resolver needs a resolve()");
  resolvers.push(r);
  return resolvers.length;
}
export async function resolveIdentity(result, pdfBytes) {
  const out = [];
  for (const r of resolvers) {
    try { const v = await r.resolve(result, pdfBytes); if (v) out.push({ source: r.name, ...v }); }
    catch (e) { out.push({ source: r.name, error: e.message }); }
  }
  return out;
}
