// Hand-written type declarations for verify-core.mjs.
//
// The engine itself is deliberately plain JS with zero dependencies — these
// types describe its actual return shapes, not an idealised API. If a field
// here and the code disagree, the code is right; please report the
// mismatch (see README.md).

/** One of the outcomes `verify()` can report. See METHODOLOGY.md in the
 * truedoc.eu repository for what each means and what would have to be true
 * for it to be wrong. */
export type VerifyStatus =
  | "no-signature"
  | "unsupported"
  | "mismatch"
  | "unverified"
  | "signed-untimed"
  | "verified-untrusted-root"
  | "verified";

export interface TimeInfo {
  value: Date | null;
  /** true if this time is proven by a timestamp authority; false if it is
   * only claimed by the signer's own software. */
  trusted: boolean;
  source: string;
}

export interface ChainLink {
  cn: string;
  notBefore?: Date;
  notAfter: Date;
}

export interface SignatureTimestampResult {
  authority: string;
  org: string | null;
  genTime: Date;
  policy: string;
  coversSignature: boolean;
  signatureValid: boolean;
  attrsCommit: boolean;
  chainValid: boolean;
  anchored: boolean;
  rootName: string;
  rootKeyFingerprint: string;
  notAfter: Date;
  chain: ChainLink[];
  valid: boolean;
  notes: string[];
  error?: string;
}

export interface RevocationInfo {
  crls: number;
  ocsps: number;
  source: string;
}

/** The per-signature-dictionary result. Every PDF may carry more than one
 * (e.g. a PAdES-LTA file with an original signature plus one or more
 * archive timestamps) — see `VerifyResult.elements`. */
export interface VerifyElement {
  kind: "doctimestamp" | "signature" | "unsupported" | "unreadable";
  label?: string;
  subFilter: string | null;
  supported: boolean;
  byteRange: [number, number, number, number];
  coversWholeFile?: boolean;
  trailingBytes?: number;
  trailingKind?: "none" | "signature-update" | "page-content" | "appended-data";
  documentMatches?: boolean | null;
  signatureValid?: boolean;
  attrsCommit?: boolean;
  chainValid?: boolean;
  anchored?: boolean;
  chainComplete?: boolean;
  withinValidity?: boolean;
  /** true only when every underlying check passed for this element. */
  authentic?: boolean;
  time?: TimeInfo;
  policy?: string | null;
  hashAlg?: string | null;
  imprint?: string | null;
  computed?: string | null;
  authority?: string;
  authorityOrg?: string | null;
  signerNotAfter?: Date;
  reason?: string | null;
  rootName?: string;
  rootFingerprint?: string;
  rootKeyFingerprint?: string;
  chain?: ChainLink[];
  signatureTimestamp?: SignatureTimestampResult | null;
  revocation?: RevocationInfo | null;
  notes: string[];
}

/** The result of `verify()`. Fields describe the OUTERMOST element — the one
 * covering the most of the file, i.e. the one that speaks for the document
 * as it currently stands. `elements` carries the full per-signature detail,
 * oldest first. */
export interface VerifyResult {
  status: VerifyStatus;
  elements: VerifyElement[];
  documentMatches?: boolean;
  hasDocumentTimestamp?: boolean;
  signatureCount?: number;
  timestampCount?: number;
  genTime?: Date | null;
  genTimeTrusted?: boolean;
  authority?: string | null;
  signedBy?: string | null;
  signedByOrg?: string | null;
  /** The latest date until which any embedded proof can still be
   * demonstrated from the file alone, or null if nothing here has a proven
   * time. See METHODOLOGY.md §6. */
  provableUntil?: Date | null;
  provableVia?: string | null;
  anchored?: boolean;
  chainComplete?: boolean;
  rootName?: string | null;
  rootFingerprint?: string | null;
  rootKeyFingerprint?: string | null;
  chain?: ChainLink[];
  hashAlg?: string | null;
  imprint?: string | null;
  computed?: string | null;
  byteRange?: [number, number, number, number];
  coversWholeFile?: boolean;
  notes: string[];
}

export interface SignatureDictionary {
  byteRange: [number, number, number, number];
  signed: Uint8Array;
  token: Uint8Array;
  subFilter: string | null;
  dictType: string | null;
  claimedTime: Date | null;
  reason: string | null;
  coversWholeFile: boolean;
  trailingBytes: number;
  trailing: string;
}

export interface KnownRoot {
  cn: string;
  spkiSha256: string;
  note: string;
}

/** The short, human-checkable list of pinned trust anchors, by public key
 * (SubjectPublicKeyInfo SHA-256), not by certificate fingerprint. See
 * METHODOLOGY.md §5 for why. */
export const KNOWN_ROOTS: KnownRoot[];

/** Scan a PDF for every `/ByteRange`-bearing signature dictionary, in file
 * order, outermost (most of the file covered) last. Exposed for callers
 * that want the raw signed byte ranges without running full verification. */
export function extractSignatures(bytes: Uint8Array): SignatureDictionary[];

/**
 * Verify every signature/timestamp embedded in a PDF.
 *
 * Runs entirely on `crypto.subtle` and plain byte parsing — no network
 * access, no filesystem access beyond the bytes you pass in. Node 20+
 * exposes `crypto.subtle` globally; browsers, Deno and Bun already do.
 *
 * @param pdfBytes  The raw bytes of the PDF file.
 * @param trustAnchors  Additional DER-encoded root certificates to trust,
 *   beyond the short pinned list in `KNOWN_ROOTS`. Most callers can omit
 *   this; see README.md for when you'd add one.
 */
export function verify(
  pdfBytes: Uint8Array,
  trustAnchors?: Uint8Array[]
): Promise<VerifyResult>;

export interface IdentityClaim {
  label: string;
  value: string;
}

export interface IdentityResolution {
  source: string;
  name?: string;
  url?: string;
  claims?: IdentityClaim[];
  error?: string;
}

export interface Resolver {
  name: string;
  resolve(result: VerifyResult, pdfBytes: Uint8Array): Promise<
    { name?: string; url?: string; claims?: IdentityClaim[] } | null
  >;
}

/** A DocTimeStamp proves WHEN, never WHO — see README.md "What this does
 * not prove". Registered resolvers are display-only and are never merged
 * into `VerifyResult` itself. */
export const resolvers: Resolver[];

export function registerResolver(resolver: Resolver): number;

export function resolveIdentity(
  result: VerifyResult,
  pdfBytes: Uint8Array
): Promise<IdentityResolution[]>;
