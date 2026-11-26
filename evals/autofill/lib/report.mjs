#!/usr/bin/env node
// Aggregate one or more runs into report.md + summary.json.
//
//   node lib/report.mjs <runId> [<runId>...] [--baseline <runId>] [--out <dir>]
//
// Several run ids merge into one report (e.g. a desktop run, an Android run
// and an iOS run of the same build). --baseline prints pass-rate deltas.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./score.mjs";

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(`--${n}`); if (i < 0) return null; const v = argv[i + 1]; argv.splice(i, 2); return v; };
const baselineId = flag("baseline");
const outDir = flag("out");
const runIds = argv.filter((a) => !a.startsWith("--"));
if (!runIds.length) { console.error("usage: node lib/report.mjs <runId>... [--baseline <runId>]"); process.exit(2); }

function load(id) {
  const p = join(ROOT, "results", id, "results.jsonl");
  if (!existsSync(p)) throw new Error(`no results at ${p}`);
  // Last record wins when a scenario was re-run within the same run id.
  const byKey = new Map();
  for (const line of readFileSync(p, "utf8").split("\n").filter(Boolean)) {
    const r = JSON.parse(line);
    byKey.set([r.tier, r.surface, r.mode, r.scenarioId].join("|"), r);
  }
  return [...byKey.values()];
}

const pct = (a, b) => (b ? `${Math.round((100 * a) / b)}%` : "–");
const median = (xs) => { const s = xs.filter((x) => x != null).sort((a, b) => a - b); return s.length ? s[Math.floor(s.length / 2)] : null; };
const ms = (x) => (x == null ? "–" : x < 1000 ? `${x} ms` : `${(x / 1000).toFixed(1)} s`);

function summarize(records) {
  const groups = new Map();
  for (const r of records) {
    const key = `${r.surface} · ${r.mode}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  const out = {};
  for (const [key, rs] of groups) {
    const fill = rs.filter((r) => (r.tier === "fixture" || r.tier === "native") && r.mode !== "in-core");
    const inCore = rs.filter((r) => r.score?.inCore);
    const live = rs.filter((r) => r.tier === "live" || r.tier === "live-app");
    const byKind = {};
    for (const r of fill) {
      const k = (byKind[r.kind] ||= { n: 0, pass: 0, expected: 0, correct: 0, filled: 0, offered: 0, offerable: 0, falseOffer: 0, negatives: 0, critical: 0, interactions: [], duration: [] });
      const s = r.score;
      k.n++; if (s.pass) k.pass++;
      k.expected += s.expected; k.correct += s.correct;
      k.filled += s.correct + s.wrong.length + s.negativesTouched.length;
      if (r.kind === "negative") { k.negatives++; if (s.falseOffer) k.falseOffer++; }
      else if (s.offered != null) { k.offerable++; if (s.offered) k.offered++; }
      k.critical += s.critical || 0;
      k.interactions.push(r.interactions); k.duration.push(r.durationMs);
    }
    const kinds = Object.keys(byKind).filter((k) => k !== "negative");
    // Headline: each kind weighs the same, so 20 login pages do not drown 6
    // card pages. Negatives and criticals are reported beside it, not in it.
    const score = kinds.length ? kinds.reduce((a, k) => a + byKind[k].pass / byKind[k].n, 0) / kinds.length : null;
    const liveAgg = live.length ? {
      n: live.length,
      reachable: live.filter((r) => r.score.reachable).length,
      offered: live.filter((r) => r.score.reachable && r.score.offered).length,
      coreFilled: live.filter((r) => r.score.reachable && r.score.coreFilled).length,
      coreApplicable: live.filter((r) => r.score.reachable && r.score.coreFilled != null).length,
      misfills: live.reduce((a, r) => a + r.score.misfills.length, 0),
      critical: live.reduce((a, r) => a + (r.score.critical || 0), 0),
      pass: live.filter((r) => r.score.pass).length,
    } : null;
    const inCoreAgg = inCore.length ? {
      n: inCore.length, pass: inCore.filter((r) => r.score.inCore.pass).length,
      passwordTouchedPage: inCore.filter((r) => r.score.inCore.passwordTouchedPage).length,
      outcomes: inCore.reduce((a, r) => ((a[r.score.inCore.outcome] = (a[r.score.inCore.outcome] || 0) + 1), a), {}),
      medianMs: median(inCore.map((r) => r.score.inCore.durationMs)),
    } : null;
    const saves = rs.filter((r) => r.tier === "save");
    const saveAgg = saves.length ? {
      n: saves.length,
      pass: saves.filter((r) => r.score.pass).length,
      shouldPrompt: saves.filter((r) => r.score.expectedPrompt !== "none").length,
      prompted: saves.filter((r) => r.score.expectedPrompt !== "none" && r.score.promptCorrect).length,
      quiet: saves.filter((r) => r.score.expectedPrompt === "none").length,
      falsePrompts: saves.filter((r) => r.score.falsePrompt).length,
      wrongValues: saves.filter((r) => r.score.promptCorrect && r.score.expectedPrompt !== "none" && !r.score.pass).length,
      stalePassword: saves.filter((r) => r.score.storedStalePassword).length,
      releases: saves.reduce((a, r) => a + (r.score.releases || 0), 0),
    } : null;
    out[key] = { score, byKind, live: liveAgg, inCore: inCoreAgg, save: saveAgg, records: rs.length };
  }
  return out;
}

function tagTable(records) {
  const tags = {};
  for (const r of records.filter((r) => r.tier === "fixture" || r.tier === "native")) {
    if (r.mode === "in-core") continue;
    for (const t of r.tags || []) { const x = (tags[t] ||= { n: 0, pass: 0 }); x.n++; if (r.score.pass) x.pass++; }
  }
  return Object.entries(tags).sort((a, b) => a[1].pass / a[1].n - b[1].pass / b[1].n);
}

function failures(records) {
  return records.filter((r) => (r.tier === "fixture" || r.tier === "native") && !(r.score.inCore ? r.score.inCore.pass : r.score.pass)).map((r) => {
    const s = r.score;
    const why = [];
    if (s.inCore) why.push(`in-core: wanted ${s.inCore.want}, got ${s.inCore.outcome}${s.inCore.passwordTouchedPage ? ", PASSWORD REACHED THE PAGE" : ""}`);
    else {
      if (s.offered === false && r.kind !== "negative") why.push("not offered");
      if (s.falseOffer) why.push("offered on a page that must not offer");
      if (s.missed.length) why.push(`missed ${s.missed.map((m) => m.key).join(", ")}`);
      if (s.wrong.length) why.push(`wrong ${s.wrong.map((m) => `${m.key}=${m.got}`).join(", ")}`);
      if (s.negativesTouched.length) why.push(`touched ${s.negativesTouched.map((m) => m.key).join(", ")}`);
      if (s.leaks.some((l) => l.critical)) why.push(`LEAK ${s.leaks.filter((l) => l.critical).map((l) => `${l.secret}→${l.key}`).join(", ")}`);
    }
    if (s.error) why.push(`error: ${s.error}`);
    return { where: `${r.surface} · ${r.mode}`, id: r.scenarioId, kind: r.kind, why: why.join("; ") };
  });
}

function render(summary, records, base) {
  const L = [];
  L.push(`# VELA autofill eval — ${runIds.join(" + ")}`, "");
  L.push(`${records.length} scenario runs. Headline score = mean pass rate over kinds (login, signup, email, identity, card), each kind weighted equally. A page passes when every expected field holds the right value, nothing else was touched, and no secret leaked.`, "");
  L.push("## Headline", "", "| Surface · mode | Score | Δ baseline | Critical | False offers | Live pass |", "|---|---:|---:|---:|---:|---:|");
  for (const [key, s] of Object.entries(summary)) {
    const crit = Object.values(s.byKind).reduce((a, k) => a + k.critical, 0) + (s.live?.critical || 0);
    const neg = s.byKind.negative;
    const b = base?.[key]?.score;
    const delta = s.score != null && b != null ? `${s.score - b >= 0 ? "+" : ""}${Math.round(100 * (s.score - b))} pt` : "–";
    L.push(`| ${key} | ${s.score == null ? "–" : pct(s.score, 1)} | ${delta} | ${crit ? `**${crit}**` : 0} | ${neg ? `${neg.falseOffer}/${neg.n}` : "–"} | ${s.live ? pct(s.live.pass, s.live.n) : "–"} |`);
  }
  L.push("", "## By kind", "", "| Surface · mode | Kind | Pages | Pass | Field recall | Field precision | Offered | Median actions | Median time |", "|---|---|---:|---:|---:|---:|---:|---:|---:|");
  for (const [key, s] of Object.entries(summary)) {
    for (const [kind, k] of Object.entries(s.byKind)) {
      L.push(`| ${key} | ${kind} | ${k.n} | ${pct(k.pass, k.n)} | ${pct(k.correct, k.expected)} | ${pct(k.correct, k.filled)} | ${kind === "negative" ? `${k.falseOffer} false` : pct(k.offered, k.offerable)} | ${median(k.interactions) ?? "–"} | ${ms(median(k.duration))} |`);
    }
  }
  const ic = Object.entries(summary).filter(([, s]) => s.inCore);
  if (ic.length) {
    L.push("", "## In-core login (password never filled into the page)", "", "| Surface | Runs | Pass | Password reached page | Outcomes | Median time |", "|---|---:|---:|---:|---|---:|");
    for (const [key, s] of ic) L.push(`| ${key} | ${s.inCore.n} | ${pct(s.inCore.pass, s.inCore.n)} | ${s.inCore.passwordTouchedPage ? `**${s.inCore.passwordTouchedPage}**` : 0} | ${Object.entries(s.inCore.outcomes).map(([o, n]) => `${o} ${n}`).join(", ")} | ${ms(s.inCore.medianMs)} |`);
  }
  const lv = Object.entries(summary).filter(([, s]) => s.live);
  if (lv.length) {
    L.push("", "## Live sites and apps", "", "Unreachable = the form did not show (bot wall, region, redesign). It is excluded from the rates.", "", "| Surface · mode | Sites | Reachable | Offered | Core field filled | Misfills | Critical | Pass |", "|---|---:|---:|---:|---:|---:|---:|---:|");
    for (const [key, s] of lv) L.push(`| ${key} | ${s.live.n} | ${s.live.reachable} | ${pct(s.live.offered, s.live.reachable)} | ${pct(s.live.coreFilled, s.live.coreApplicable)} | ${s.live.misfills} | ${s.live.critical ? `**${s.live.critical}**` : 0} | ${pct(s.live.pass, s.live.reachable)} |`);
  }
  const sv = Object.entries(summary).filter(([, s]) => s.save);
  if (sv.length) {
    L.push("", "## Saving and updating logins", "",
      "After a person types and submits: the right prompt (save a new login, update a known one, or nothing), with the typed username and the new password, stored for the right site and item. Secret releases = stored passwords the host handed out during capture, before the person chose anything.", "",
      "| Surface | Scenarios | Pass | Prompted when it should | False prompts | Wrong values | Stored old password | Secret releases |", "|---|---:|---:|---:|---:|---:|---:|---:|");
    for (const [key, s] of sv) {
      const x = s.save;
      L.push(`| ${key} | ${x.n} | ${pct(x.pass, x.n)} | ${pct(x.prompted, x.shouldPrompt)} | ${x.falsePrompts}/${x.quiet} | ${x.wrongValues} | ${x.stalePassword ? `**${x.stalePassword}**` : 0} | ${x.releases} |`);
    }
    const bad = records.filter((r) => r.tier === "save" && !r.score.pass);
    if (bad.length) {
      L.push("", "| Save scenario | Why |", "|---|---|");
      for (const r of bad) L.push(`| ${r.scenarioId} | ${r.score.problems.join("; ").replace(/\|/g, "\\|")} |`);
    }
  }
  const tags = tagTable(records);
  if (tags.length) {
    L.push("", "## Hardest page archetypes (all fill modes)", "", "| Tag | Runs | Pass |", "|---|---:|---:|");
    for (const [t, x] of tags.slice(0, 20)) L.push(`| ${t} | ${x.n} | ${pct(x.pass, x.n)} |`);
  }
  const f = failures(records);
  if (f.length) {
    L.push("", `## Failures (${f.length})`, "", "| Surface · mode | Scenario | Kind | Why |", "|---|---|---|---|");
    for (const x of f) L.push(`| ${x.where} | ${x.id} | ${x.kind} | ${x.why.replace(/\|/g, "\\|")} |`);
  }
  return L.join("\n") + "\n";
}

const records = runIds.flatMap(load);
const summary = summarize(records);
const base = baselineId ? summarize(load(baselineId)) : null;
const md = render(summary, records, base);
const dir = outDir || join(ROOT, "results", runIds[0]);
writeFileSync(join(dir, "report.md"), md);
writeFileSync(join(dir, "summary.json"), JSON.stringify(summary, (k, v) => (k === "interactions" || k === "duration" ? undefined : v), 2));
process.stdout.write(md);
