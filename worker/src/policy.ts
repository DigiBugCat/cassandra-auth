/**
 * ACL policy management — supports KV-stored JSON (primary) and baked-in YAML (fallback).
 *
 * KV key: `acl:policy` in ACL_CREDENTIALS namespace.
 * If KV has no policy, falls back to the YAML baked into the worker bundle at build time.
 */
import aclYaml from "../../env/acl.yaml";
import { parse } from "yaml";
import type { AclConfig, PolicyLine } from "./types";

const KV_KEY = "acl:policy";

/** Parse an AclConfig into Casbin-compatible policy lines. */
export function buildPolicies(config: AclConfig): PolicyLine[] {
  const policies: PolicyLine[] = [];

  const add = (ptype: string, v0: string, v1: string, v2: string, v3: string) => {
    policies.push({ ptype, v0, v1, v2, v3 });
  };

  // Groups
  if (config.groups) {
    for (const [group, def] of Object.entries(config.groups)) {
      for (const [svc, svcDef] of Object.entries(def.services)) {
        if (svcDef.access === "allow") {
          add("p", group, svc, "*", "allow");
        }
        if (svcDef.tools?.deny) {
          for (const tool of svcDef.tools.deny) {
            add("p", group, svc, tool, "deny");
          }
        }
        if (svcDef.tools?.allow) {
          for (const tool of svcDef.tools.allow) {
            add("p", group, svc, tool, "allow");
          }
        }
      }
    }
  }

  // Users
  if (config.users) {
    for (const [email, user] of Object.entries(config.users)) {
      if (user.role === "admin") {
        add("p", email, "*", "*", "allow");
      }
      if (user.groups) {
        for (const grp of user.groups) {
          add("g", email, grp, "", "");
        }
      }
    }
  }

  // Domains
  if (config.domains) {
    for (const [domain, def] of Object.entries(config.domains)) {
      if (def.groups) {
        for (const grp of def.groups) {
          add("g", `domain:${domain}`, grp, "", "");
        }
      }
    }
  }

  return policies;
}

/** Default config parsed from baked-in YAML (fallback when KV has no policy). */
export const DEFAULT_CONFIG: AclConfig = parse(aclYaml) as AclConfig;

/** Load ACL config from KV. Returns null if no policy stored. */
export async function loadConfigFromKV(kv: KVNamespace): Promise<AclConfig | null> {
  const raw = await kv.get(KV_KEY, "json");
  return raw as AclConfig | null;
}

/** Save ACL config to KV. */
export async function saveConfigToKV(kv: KVNamespace, config: AclConfig): Promise<void> {
  await kv.put(KV_KEY, JSON.stringify(config));
}
