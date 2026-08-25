// Deno / Bun quickstart. Both expose crypto.subtle and Deno.readFile /
// Bun's Node-compatible fs, so this runs unchanged on either runtime:
//
//   deno run --allow-read examples/deno.mjs path/to/document.pdf
//   bun run examples/deno.mjs path/to/document.pdf
//
// Deno resolves "verifiedby" via an import map or npm: specifier; Bun
// resolves it exactly like Node after `bun add verifiedby` / `npm install`.
// Using the npm: specifier here so the same file works on both without an
// import map:
import { verify } from "npm:verifiedby";

const path = (globalThis.Deno ? Deno.args[0] : process.argv[2]);
if (!path) {
  console.error("usage: <runtime> examples/deno.mjs <file.pdf>");
  (globalThis.Deno ?? { exit: process.exit }).exit(2);
}

const bytes = globalThis.Deno
  ? await Deno.readFile(path)
  : new Uint8Array(await (await import("node:fs/promises")).readFile(path));

const result = await verify(bytes);
console.log(result.status, "-", result.notes?.[0] ?? "");
