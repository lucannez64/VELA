import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const VERSION_FILES = [
  "package.json",
  "manifest.json",
  "manifests/chrome.json",
  "manifests/firefox.json"
];

function parseVersion(version) {
  const parts = version.split(".");
  if (parts.length !== 3 || parts.some(part => !/^\d+$/.test(part))) {
    throw new Error(`Unsupported version format: ${version}`);
  }
  return parts.map(part => Number.parseInt(part, 10));
}

function bumpPatch(version) {
  const [major, minor, patch] = parseVersion(version);
  return `${major}.${minor}.${patch + 1}`;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, data) {
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
}

const packagePath = join(__dirname, "package.json");
const currentVersion = readJson(packagePath).version;
const nextVersion = bumpPatch(currentVersion);

for (const relativePath of VERSION_FILES) {
  const path = join(__dirname, relativePath);
  const data = readJson(path);
  data.version = nextVersion;
  writeJson(path, data);
}

console.log(`Bumped extension version: ${currentVersion} -> ${nextVersion}`);
