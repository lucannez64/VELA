#!/usr/bin/env node
// Write the eval vault as an unencrypted Bitwarden JSON export, which every
// VELA client imports (libVELA/vela-import). Use it to load the eval data into
// a *dedicated test account* for --host real, Android and iOS runs.
//
//   node lib/export-vault.mjs [--live] [out.json]
//
// --live adds one login per live site (the synthetic _live credentials), so
// the live tier has something to offer on every site.
//
// Not carried by the importer, set by hand after import: the lab app's
// package/bundle id on the "Autofill Lab (app)" login (see README).
import { writeFileSync } from "node:fs";
import { loadCorpus } from "./score.mjs";

const live = process.argv.includes("--live");
const out = process.argv.slice(2).find((a) => !a.startsWith("--")) || "vela-eval-vault.bitwarden.json";
const { vault, liveSites } = loadCorpus();

const items = [];
for (const l of vault.logins) {
  items.push({
    type: 1, name: l.name, favorite: false, notes: "VELA autofill eval fixture (fake credentials)",
    login: {
      username: l.username, password: l.password, totp: null,
      uris: [{ uri: l.url }, ...(l.appIds || []).map((a) => ({ uri: `androidapp://${a}` }))],
    },
  });
}
if (live) {
  const hosts = new Set();
  for (const s of liveSites.sites) {
    const h = new URL(s.url).hostname.replace(/^www\./, "");
    if (hosts.has(h)) continue;
    hosts.add(h);
    items.push({ type: 1, name: `eval: ${h}`, login: { username: vault._live.username, password: vault._live.password, uris: [{ uri: `https://${h}/` }] } });
  }
}
for (const c of vault.cards) {
  const [mm, yy] = c.exp.split("/");
  items.push({ type: 3, name: c.name, card: { cardholderName: c.cardholderName, number: c.number, expMonth: String(Number(mm)), expYear: yy.length === 2 ? `20${yy}` : yy, code: c.cvv, brand: "Visa" } });
}
// Bitwarden identities hold one address each, so each address becomes its
// own identity, named after its label.
for (const i of vault.identities) {
  for (const a of i.addresses) {
    items.push({
      type: 4, name: `${i.name} (${a.label})`,
      identity: {
        firstName: i.firstName, middleName: i.middleName || null, lastName: i.lastName, email: i.email, phone: i.phone, company: i.company,
        address1: a.line1, address2: a.line2 || null, city: a.city, state: a.region, postalCode: a.postalCode, country: a.countryCode,
      },
    });
  }
}
writeFileSync(out, JSON.stringify({ encrypted: false, folders: [], items }, null, 2));
console.log(`wrote ${items.length} items to ${out}`);
