// Example: role-based per-member features (the manage domain's model, resolved by ReBAC).
//
// Different members of the same org get DIFFERENT feature subsets via their ROLE — not by per-member
// grants. A role `grants` features; a member is `assignee` of a role; ACCESS.CHECK resolves
// can_use(member, feat) → role that grants it ← member is assignee (one hop, the {grants,assignee} rule).
//
//   cd instance && cargo run -p lotord        # standalone (demo ReBAC schema incl. grants/assignee)
//   cd lotor-sdk-ts && pnpm roles
//
// In production the control plane's `manage` domain (orgs/roles/invitations) emits exactly these
// tuples into the bundle; here the example writes them directly to show the resolution.

import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";
const run = Date.now().toString(36);

const EDITOR = "role:editor";
const VIEWER = "role:viewer";

async function main() {
  const lotor = await LotorClient.connect({ host, port });
  await lotor.auth(apiKey);

  // Roles → features (what the org admin / manage domain defines).
  await lotor.accessGrant(EDITOR, "grants", "feat:x");
  await lotor.accessGrant(EDITOR, "grants", "feat:y");
  await lotor.accessGrant(VIEWER, "grants", "feat:x");
  console.log("roles: editor grants [x, y]; viewer grants [x]\n");

  // Members assigned to roles.
  const alice = `user:alice-${run}`;
  const bob = `user:bob-${run}`;
  await lotor.accessGrant(alice, "assignee", EDITOR);
  await lotor.accessGrant(bob, "assignee", VIEWER);
  console.log(`${alice} → editor;  ${bob} → viewer\n`);

  for (const [who, member] of [["alice (editor)", alice], ["bob (viewer)", bob]] as const) {
    console.log(`— ${who} —`);
    for (const f of ["x", "y"]) console.log(`  feature ${f}:`, await useFeature(lotor, member, f));
  }

  await lotor.quit();
}

async function useFeature(lotor: LotorClient, member: string, feature: string): Promise<string> {
  const can = await lotor.accessCheck(member, "can_use", `feat:${feature}`);
  if (!can.allow) return `403 ${can.reason} (role doesn't grant feat:${feature})`;
  const u = await lotor.meterConsume(member, `feat_${feature}`, 1);
  return u.accepted ? `200 ok (used ${u.used}/${u.max})` : `429 ${u.reason}`;
}

main().catch((e) => { console.error(e); process.exit(1); });
