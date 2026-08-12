import assert from "node:assert/strict";
import * as fs from "node:fs";
import { describe, test } from "node:test";
import { assertPackageContents, assertPackageMetadata, verifyPackageContents } from "../../scripts/verify-package-contents.mjs";

const current = verifyPackageContents(process.cwd());
const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"));

describe("npm release package policy", () => {
  test("accepts the current built package", () => {
    assert.equal(current.package.name, "@lotor.dev/sdk");
    assert.equal(current.paths.length, 13);
  });

  test("rejects unsafe or unexpected package paths", () => {
    for (const invalid of [
      { path: "../secret.md", size: 1, mode: 0o644 },
      { path: "tests/secret.ts", size: 1, mode: 0o644 },
      { path: "dist/executable.js", size: 1, mode: 0o755 },
    ]) assert.throws(() => assertPackageContents([...current.package.files, invalid]), /Package invariant failed/);
    assert.throws(() => assertPackageContents(current.package.files.slice(1)), /reviewed allowlist/);
  });

  test("rejects unsafe metadata and lifecycle scripts", () => {
    assert.doesNotThrow(() => assertPackageMetadata(current.package, packageJson, current.paths.length));
    assert.throws(() => assertPackageMetadata(current.package, { ...packageJson, scripts: { ...packageJson.scripts, prepack: "node payload.js" } }, current.paths.length), /lifecycle script/);
    assert.throws(() => assertPackageMetadata(current.package, { ...packageJson, publishConfig: { ...packageJson.publishConfig, provenance: false } }, current.paths.length), /provenance/);
  });
});
