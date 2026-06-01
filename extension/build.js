import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, readdirSync, statSync, copyFileSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ROOT = __dirname;
const DIST = join(ROOT, "dist");
const POLYFILL_SRC = join(ROOT, "node_modules", "webextension-polyfill", "dist", "browser-polyfill.js");

const BROWSERS = ["chrome", "firefox"];
const XPI_NAME = "vela-firefox.xpi";

const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < CRC_TABLE.length; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[i] = c >>> 0;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const year = Math.max(date.getFullYear(), 1980);
  const dosTime =
    (date.getHours() << 11) |
    (date.getMinutes() << 5) |
    Math.floor(date.getSeconds() / 2);
  const dosDate =
    ((year - 1980) << 9) |
    ((date.getMonth() + 1) << 5) |
    date.getDate();
  return { dosTime, dosDate };
}

function collectFiles(root, dir = root, files = []) {
  for (const entry of readdirSync(dir).sort()) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      collectFiles(root, path, files);
    } else {
      files.push({
        path,
        name: relative(root, path).split(sep).join("/"),
        stat
      });
    }
  }
  return files;
}

function createZipFromDirectory(sourceDir, outputPath) {
  const chunks = [];
  const centralDirectory = [];
  let offset = 0;

  for (const file of collectFiles(sourceDir)) {
    const data = readFileSync(file.path);
    const name = Buffer.from(file.name, "utf8");
    const checksum = crc32(data);
    const { dosTime, dosDate } = dosDateTime(file.stat.mtime);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    localHeader.writeUInt16LE(0, 28);

    chunks.push(localHeader, name, data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(data.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralDirectory.push(centralHeader, name);

    offset += localHeader.length + name.length + data.length;
  }

  const centralDirectorySize = centralDirectory.reduce((sum, chunk) => sum + chunk.length, 0);
  const endRecord = Buffer.alloc(22);
  endRecord.writeUInt32LE(0x06054b50, 0);
  endRecord.writeUInt16LE(0, 4);
  endRecord.writeUInt16LE(0, 6);
  endRecord.writeUInt16LE(centralDirectory.length / 2, 8);
  endRecord.writeUInt16LE(centralDirectory.length / 2, 10);
  endRecord.writeUInt32LE(centralDirectorySize, 12);
  endRecord.writeUInt32LE(offset, 16);
  endRecord.writeUInt16LE(0, 20);

  const archive = Buffer.concat([...chunks, ...centralDirectory, endRecord]);
  try {
    writeFileSync(outputPath, archive);
    return outputPath;
  } catch (error) {
    const fallbackPath = outputPath.replace(/\.xpi$/i, `-${Date.now()}.xpi`);
    writeFileSync(fallbackPath, archive);
    console.warn(`  WARNING: Could not replace ${outputPath}: ${error.message}`);
    return fallbackPath;
  }
}

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

  if (browser === "firefox") {
    const xpiPath = join(DIST, XPI_NAME);
    const writtenXpiPath = createZipFromDirectory(browserDist, xpiPath);
    console.log(`  Packaged: ${writtenXpiPath}`);
  }
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
