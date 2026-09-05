import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

export const EXPECTED_PACKAGE_FILES = Object.freeze(["dist", "CHANGELOG.md", "SECURITY.md"]);
export const REQUIRED_PACKAGE_PATHS = Object.freeze([
  "package.json",
  "README.md",
  "LICENSE",
  "CHANGELOG.md",
  "SECURITY.md",
  "dist/client.d.ts",
  "dist/client.js",
  "dist/control.d.ts",
  "dist/control.js",
  "dist/gateway-assertion.d.ts",
  "dist/gateway-assertion.js",
  "dist/index.d.ts",
  "dist/index.js",
  "dist/ownership.d.ts",
  "dist/ownership.js",
  "dist/wire.d.ts",
  "dist/wire.js",
]);

const FORBIDDEN_LIFECYCLE_SCRIPTS = Object.freeze([
  "preinstall", "install", "postinstall", "prepack", "prepare", "postpack",
  "prepublish", "prepublishOnly", "publish", "postpublish",
]);
const ALLOWED_EXTENSIONS = new Set(["", ".json", ".md", ".ts", ".js"]);

function invariant(condition, message) {
  if (!condition) throw new Error(`Package invariant failed: ${message}`);
}

export function assertPackageContents(files) {
  invariant(Array.isArray(files), "npm pack output must contain a files array");
  invariant(files.length > 0 && files.length <= 100, "package must contain between 1 and 100 files");
  const paths = files.map((file) => {
    invariant(file && typeof file.path === "string", "each package file must have a string path");
    const normalized = path.posix.normalize(file.path);
    const segments = file.path.split("/");
    invariant(normalized === file.path && !file.path.startsWith("/") && segments.every((segment) => segment && segment !== "." && segment !== ".."), `unsafe package path: ${file.path}`);
    invariant(ALLOWED_EXTENSIONS.has(path.posix.extname(file.path)), `unsupported package file type: ${file.path}`);
    invariant(Number.isInteger(file.size) && file.size >= 0 && file.size <= 5 * 1024 * 1024, `invalid file size: ${file.path}`);
    invariant(file.mode === 0o644, `package files must be non-executable: ${file.path}`);
    return file.path;
  });
  invariant(new Set(paths).size === paths.length, "package must not contain duplicate paths");
  invariant(JSON.stringify([...paths].sort()) === JSON.stringify([...REQUIRED_PACKAGE_PATHS].sort()), "package paths must exactly match the reviewed allowlist");
  return paths;
}

export function assertPackageMetadata(packageData, packageJson, pathCount) {
  invariant(packageJson.name === "@lotor.dev/sdk", "package name must be @lotor.dev/sdk");
  invariant(packageData.name === packageJson.name, "packed name must match package.json");
  invariant(packageData.version === packageJson.version, "packed version must match package.json");
  invariant(packageData.id === `${packageJson.name}@${packageJson.version}`, "packed id must match name and version");
  invariant(packageData.filename === `lotor.dev-sdk-${packageJson.version}.tgz`, "tarball filename must match name and version");
  invariant(packageData.entryCount === pathCount, "npm entry count must match audited paths");
  invariant(Number.isInteger(packageData.size) && packageData.size > 0 && packageData.size <= 5 * 1024 * 1024, "tarball size must be safe");
  invariant(Number.isInteger(packageData.unpackedSize) && packageData.unpackedSize > 0 && packageData.unpackedSize <= 15 * 1024 * 1024, "unpacked size must be safe");
  invariant(Array.isArray(packageData.bundled) && packageData.bundled.length === 0, "package must not bundle dependencies");
  invariant(JSON.stringify(packageJson.files) === JSON.stringify(EXPECTED_PACKAGE_FILES), "package files policy must remain exact");
  invariant(packageJson.main === "./dist/index.js" && packageJson.module === "./dist/index.js" && packageJson.types === "./dist/index.d.ts", "package entry points must remain exact");
  invariant(packageJson.engines?.node === ">=22.14.0", "Node engine must remain >=22.14.0");
  invariant(packageJson.repository?.url === "git+https://github.com/2kims/lotor-sdk.git", "repository URL must be canonical");
  invariant(packageJson.publishConfig?.access === "public", "publish access must be public");
  invariant(packageJson.publishConfig?.registry === "https://registry.npmjs.org/", "publish registry must be npmjs");
  invariant(packageJson.publishConfig?.provenance === true, "package provenance must be enabled");
  invariant(packageJson.private === undefined, "package must not be private");
  for (const script of FORBIDDEN_LIFECYCLE_SCRIPTS) invariant(!Object.hasOwn(packageJson.scripts ?? {}, script), `package lifecycle script is forbidden: ${script}`);
}

export function verifyPackageContents(rootDir = process.cwd()) {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const result = spawnSync(npm, ["pack", "--dry-run", "--ignore-scripts", "--json"], { cwd: rootDir, encoding: "utf8", shell: false });
  if (result.error) throw new Error(`Could not run npm pack: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`npm pack --dry-run failed: ${result.stderr.trim() || result.stdout.trim()}`);
  const payload = JSON.parse(result.stdout);
  invariant(Array.isArray(payload) && payload.length === 1, "npm pack must describe exactly one package");
  const packageJson = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8"));
  const paths = assertPackageContents(payload[0].files);
  assertPackageMetadata(payload[0], packageJson, paths.length);
  return { package: payload[0], paths };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const result = verifyPackageContents();
    console.log(`Verified ${result.paths.length} files in ${result.package.filename}.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
