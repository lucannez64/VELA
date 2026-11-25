#!/usr/bin/env node
// Add the sites from your own vault to the live tier, domains only.
//
//   export VELA_SESSION=...   # from `vela unlock`
//   vela list items --json | node lib/vault-sites.mjs
//
// Writes corpus/live-sites.local.json (gitignored: it is a map of the accounts
// you hold). Usernames, names and passwords are never read past this filter.
// Domains already covered by corpus/live-sites.json are skipped.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./score.mjs";

const MULTI = new Set(["co.uk", "com.au", "co.jp", "com.br", "gouv.fr", "gov.uk", "co.nz", "com.mx"]);
const registrable = (h) => { const p = h.split("."); const l2 = p.slice(-2).join("."); return MULTI.has(l2) ? p.slice(-3).join(".") : l2; };
const isPrivate = (h) => /\.(local|lan|home|internal|ts\.net|test)$/.test(h) || /^\d+\.\d+\.\d+\.\d+$/.test(h) || h === "localhost" || !h.includes(".");

const rows = JSON.parse(readFileSync(0, "utf8"));
const shared = JSON.parse(readFileSync(join(ROOT, "corpus/live-sites.json"), "utf8")).sites;
const known = new Set(shared.map((s) => registrable(new URL(s.url).hostname)));
const hosts = new Set();
for (const r of rows) {
  if (r.type !== "login" || !r.url) continue;
  for (const u of String(r.url).split(/[\s,]+/)) {
    try {
      const h = new URL(u.includes("://") ? u : `https://${u}`).hostname.replace(/^www\./, "").toLowerCase();
      if (!isPrivate(h) && !known.has(registrable(h))) hosts.add(h);
    } catch {}
  }
}
const sites = [...hosts].sort().map((h) => ({
  id: `vault-${h.replace(/[^a-z0-9]+/g, "-")}`, url: `https://${h}/`, kind: "login", category: "vault", tags: ["from-vault", "discover-login"],
}));
writeFileSync(join(ROOT, "corpus/live-sites.local.json"), JSON.stringify({
  _comment: "Sites from your own vault (domains only). Local file, gitignored: it is a map of the accounts you hold. Regenerate rather than commit.", sites,
}, null, 2) + "\n");
console.log(`${sites.length} vault sites written to corpus/live-sites.local.json`);
