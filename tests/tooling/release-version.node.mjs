import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, test } from "node:test";
import { verifyRootReleaseVersion } from "../../scripts/verify-release-version.mjs";

function fixture(manifest = "1.2.3", packageVersion = "1.2.3") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lotor-release-version-"));
  fs.writeFileSync(path.join(dir, ".release-please-manifest.json"), JSON.stringify({ ".": manifest }));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ version: packageVersion }));
  return dir;
}

describe("root release version", () => {
  test("accepts matching metadata", () => {
    assert.match(verifyRootReleaseVersion(process.cwd()), /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  });

  test("rejects mismatches and malformed versions", () => {
    const mismatch = fixture("1.2.3", "1.2.4");
    const malformed = fixture("1.2.3-01", "1.2.3-01");
    try {
      assert.throws(() => verifyRootReleaseVersion(mismatch), /mismatch/);
      assert.throws(() => verifyRootReleaseVersion(malformed), /valid semantic version/);
    } finally {
      fs.rmSync(mismatch, { recursive: true, force: true });
      fs.rmSync(malformed, { recursive: true, force: true });
    }
  });
});
