// Example: organization members + per-member feature gating & metering — with ReBAC inheritance.
//
// The org "subscribes" to a plan = a set of features, granted ONCE at the org level. Members are just
// added to the org; each member inherits the org's features automatically (ACCESS.CHECK resolves
// member → org → has feature via the relation schema). Usage of each feature is still metered per
// member, independently.
//
//   cd instance && cargo run -p lotord        # standalone (demo data: ReBAC schema + feat_x/y/z meters)
//   cd lotor-sdk-ts && pnpm org
//
// Real today: membership/entitlement tuples (ACCESS.GRANT), inherited checks (ACCESS.CHECK + ReBAC),
// per-member metering (METER.CONSUME scope=member), member listing (ACCESS.EXPAND).
// Next (manage domain): the invitation lifecycle (pending ticket → accept) and roles, so members can
// have *different* feature subsets within one org via their role rather than all sharing the org plan.

import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";

const ORG = "org:acme";
const ORG_PLAN = ["x", "y"]; // features the org's plan includes (NOT z)
const run = Date.now().toString(36); // fresh member ids each run (counters are durable per scope)

async function main() {
  const lotor = await LotorClient.connect({ host, port });
  await lotor.auth(apiKey);

  // The org subscribes to its plan — features granted once, at the org level.
  for (const f of ORG_PLAN) await lotor.accessGrant(ORG, "has", `feat:${f}`);
  console.log(`${ORG} plan includes features [${ORG_PLAN.join(", ")}]\n`);

  // Add members — no per-member feature grants; they inherit the org plan.
  const alice = `user:alice-${run}`;
  const bob = `user:bob-${run}`;
  await addMember(lotor, alice);
  await addMember(lotor, bob);

  const members = await lotor.accessExpand(ORG, "member");
  console.log(`members of ${ORG}: ${members.join(", ")}\n`);

  console.log("— alice uses feature x (inherited; per-member quota 3) until exhausted —");
  for (let i = 1; i <= 4; i++) console.log(`  call ${i}:`, await useFeature(lotor, alice, "x"));

  console.log("\n— alice's other features —");
  console.log("  feature y:", await useFeature(lotor, alice, "y")); // inherited
  console.log("  feature z:", await useFeature(lotor, alice, "z")); // org plan lacks z -> 403

  console.log("\n— bob uses feature x: inherited too, on his OWN counter —");
  console.log("  call 1:", await useFeature(lotor, bob, "x"));

  await lotor.quit();
}

// Add a member to the org — that's it. Feature access is inherited from the org's plan.
async function addMember(lotor: LotorClient, member: string) {
  await lotor.accessGrant(member, "member", ORG);
  console.log(`added ${member} to ${ORG} (inherits the org plan)`);
}

// Gate (inherited entitlement) then meter (per-member quota).
async function useFeature(lotor: LotorClient, member: string, feature: string): Promise<string> {
  const can = await lotor.accessCheck(member, "can_use", `feat:${feature}`);
  if (!can.allow) return `403 ${can.reason} for feat:${feature}`;
  const usage = await lotor.meterConsume(member, `feat_${feature}`, 1);
  if (!usage.accepted) return `429 ${usage.reason} (used ${usage.used}/${usage.max})`;
  return `200 ok (${member} used ${usage.used}/${usage.max} of feat_${feature})`;
}

main().catch((e) => { console.error(e); process.exit(1); });
