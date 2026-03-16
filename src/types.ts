import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export type McpCredentials = Record<string, string>;

/** Base env bindings every MCP worker needs. Services extend this with their own bindings. */
export interface McpAuthEnv {
  OAUTH_KV: KVNamespace;
  MCP_KEYS: KVNamespace;
  MCP_OBJECT: DurableObjectNamespace;
  WORKOS_CLIENT_ID: string;
  WORKOS_CLIENT_SECRET: string;
  COOKIE_ENCRYPTION_KEY: string;
  VM_PUSH_URL: string;
  VM_PUSH_CLIENT_ID: string;
  VM_PUSH_CLIENT_SECRET: string;
  /** Auth service URL — optional, enables per-tool authorization when set. */
  AUTH_URL?: string;
  /** Shared secret for Auth service-to-service auth. */
  AUTH_SECRET?: string;
}

/** Resolved identity + per-key credentials from token resolution. */
export interface ResolvedAuth<TCredentials extends McpCredentials = McpCredentials> {
  userId: string;
  email: string;
  name: string;
  accessToken: string;
  /** Per-key service credentials (e.g. Pushover user key). Only present for mcp_ keys with credentials. */
  credentials?: TCredentials;
}

/** Props stored in the McpAgent Durable Object. */
export interface McpAgentProps<TCredentials extends McpCredentials = McpCredentials>
  extends ResolvedAuth<TCredentials> {
  [key: string]: unknown;
}

/** Metadata stored in MCP_KEYS KV. */
export interface McpKeyMeta<TCredentials extends McpCredentials = McpCredentials> {
  name?: string;
  service?: string;
  created_by?: string;
  credentials?: TCredentials;
}

/** Config for createMcpWorker factory. */
export interface McpWorkerConfig<
  TEnv extends McpAuthEnv = McpAuthEnv,
  TCredentials extends McpCredentials = McpCredentials,
> {
  /** Service identifier — must match the service field in MCP key metadata. */
  serviceId: string;
  /** Human-readable server name for MCP protocol. */
  name: string;
  /** Server version for MCP protocol. */
  version?: string;
  /** Register MCP tools on the server. Called once per Durable Object init. */
  registerTools: (
    server: McpServer,
    env: TEnv,
    auth: ResolvedAuth<TCredentials>,
  ) => void | Promise<void>;
}
