export interface CheckRequest {
  email: string;
  service: string;
  tool: string;
}

export interface CheckResponse {
  allowed: boolean;
  reason: string;
}

export interface PolicyLine {
  ptype: string;
  v0: string;
  v1: string;
  v2: string;
  v3: string;
}

// ── ACL Config (KV-stored policy) ──

export interface AclServiceConfig {
  access?: "allow" | "deny";
  tools?: { allow?: string[]; deny?: string[] };
}

export interface AclGroup {
  services: Record<string, AclServiceConfig>;
}

export interface AclUser {
  role?: "admin" | "user";
  services?: "*" | string[];
  groups?: string[];
}

export interface AclDomain {
  role?: "admin" | "user";
  groups?: string[];
}

export interface AclConfig {
  default: "allow" | "deny";
  groups?: Record<string, AclGroup>;
  users?: Record<string, AclUser>;
  domains?: Record<string, AclDomain>;
}
