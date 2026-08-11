#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const declarations = ["client.d.ts", "index.d.ts", "ownership.d.ts"];
const update = process.argv.slice(2).includes("--update");

for (const declaration of declarations) {
  const generated = readFileSync(join(root, "dist", declaration), "utf8");
  const snapshot = join(root, "api", declaration);
  if (update) {
    mkdirSync(dirname(snapshot), { recursive: true });
    writeFileSync(snapshot, generated);
    continue;
  }
  let approved;
  try {
    approved = readFileSync(snapshot, "utf8");
  } catch {
    throw new Error(`missing API snapshot: api/${declaration}; run pnpm api:update and review it`);
  }
  if (generated !== approved) {
    throw new Error(`public declaration drift: api/${declaration}; run pnpm api:update and review the diff`);
  }
}

process.stdout.write(update ? "updated public API snapshots\n" : "public API declarations match reviewed snapshots\n");
