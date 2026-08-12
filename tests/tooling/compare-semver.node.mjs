import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { compareSemVer } from "../../scripts/compare-semver.mjs";

describe("release semantic-version comparison", () => {
  test("orders stable and prerelease versions", () => {
    assert.equal(compareSemVer("1.0.0", "1.0.0-rc.1"), 1);
    assert.equal(compareSemVer("1.0.0-rc.2", "1.0.0-rc.1"), 1);
    assert.equal(compareSemVer("1.0.0", "1.0.0"), 0);
  });

  test("rejects inexact versions", () => {
    for (const value of ["v1.0.0", "1.0", "01.0.0", "1.0.0-01", "latest"]) {
      assert.throws(() => compareSemVer(value, "1.0.0"), /Invalid exact semantic version/);
    }
  });
});
