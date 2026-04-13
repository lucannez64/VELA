import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, readdirSync, statSync, copyFileSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ROOT = __dirname;
const DIST = join(ROOT, "dist");
const POLYFILL_SRC = join(ROOT, "node_modules", "webextension-polyfill", "dist", "browser-polyfill.js");

const BROWSERS = ["chrome", "firefox"];

function copyRecursive(src, dest) {
  if (!existsSync(src)) return;
  const stat = statSync(src);
  if (stat.isDirectory()) {
    if (!existsSync(dest)) mkdirSync(dest, { recursive: true });
    for (const entry of readdirSync(src)) {
      copyRecursive(join(src, entry), join(dest, entry));
    }
  } else {
    const dir = dirname(dest);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    copyFileSync(src, dest);
  }
}

function buildBrowser(browser) {
  const browserDist = join(DIST, browser);
  if (existsSync(browserDist)) {
    rmSync(browserDist, { recursive: true });
  }
  mkdirSync(browserDist, { recursive: true });

  if (!existsSync(POLYFILL_SRC)) {
    console.error("ERROR: webextension-polyfill not found. Run 'bun install' first.");
    process.exit(1);
  }
  const sharedDir = join(browserDist, "shared");
  mkdirSync(sharedDir, { recursive: true });
  copyFileSync(POLYFILL_SRC, join(sharedDir, "browser-polyfill.js"));

  const manifestSrc = join(ROOT, "manifests", `${browser}.json`);
  if (!existsSync(manifestSrc)) {
    console.error(`ERROR: Manifest not found: ${manifestSrc}`);
    process.exit(1);
  }
  copyFileSync(manifestSrc, join(browserDist, "manifest.json"));

  copyRecursive(join(ROOT, "src", "background"), join(browserDist, "background"));
  copyRecursive(join(ROOT, "src", "content"), join(browserDist, "content"));
  copyRecursive(join(ROOT, "src", "popup"), join(browserDist, "popup"));
  copyRecursive(join(ROOT, "src", "shared", "autofill-utils.js"), join(browserDist, "shared", "autofill-utils.js"));

  copyRecursive(join(ROOT, "_locales"), join(browserDist, "_locales"));
  copyRecursive(join(ROOT, "icons"), join(browserDist, "icons"));

  console.log(`  Built: ${browserDist}`);
}

function main() {
  const args = process.argv.slice(2);

  let targets;
  if (args.includes("--chrome") && !args.includes("--firefox")) {
    targets = ["chrome"];
  } else if (args.includes("--firefox") && !args.includes("--chrome")) {
    targets = ["firefox"];
  } else if (args.length > 0 && !args.includes("--chrome") && !args.includes("--firefox")) {
    console.error("Usage: bun run build.js [--chrome] [--firefox]");
    process.exit(1);
  } else {
    targets = BROWSERS;
  }

  console.log("Building VELA extension...");
  for (const browser of targets) {
    buildBrowser(browser);
  }
  console.log("Done.");
}

main();
