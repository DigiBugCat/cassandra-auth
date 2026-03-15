/**
 * Parse env/acl.yaml (imported as text at build time) into Casbin policy lines.
 * The YAML is baked into the worker bundle — no D1 or external push needed.
 * To update policy: edit env/acl.yaml and redeploy.
 */
import aclYaml from "../../env/acl.yaml";
import { parse } from "yaml";
import type { PolicyLine } from "./types";

interface AclGroup {
  services: Record<string, {
    access?: "allow" | "deny";
    tools?: {
      allow?: string[];
      deny?: string[];
    };
  }>;
}

interface AclUser {
  role?: "admin" | "user";
  services?: "*" | string[];
  groups?: string[];
}

interface AclDomain {
  role?: "admin" | "user";
  groups?: string[];
}

interface AclConfig {
  default: "allow" | "deny";
  groups?: Record<string, AclGroup>;
  users?: Record<string, AclUser>;
  domains?: Record<string, AclDomain>;
}

function buildPolicies(config: AclConfig): PolicyLine[] {
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

const config = parse(aclYaml) as AclConfig;
export const POLICIES = buildPolicies(config);
