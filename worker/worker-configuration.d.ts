interface Env {
  AUTH_CREDENTIALS: KVNamespace;
  MCP_KEYS: KVNamespace;
  AUTH_SECRET: string;
  CF_ACCESS_CLIENT_ID?: string;
  VM_PUSH_URL: string;
  VM_PUSH_CLIENT_ID: string;
  VM_PUSH_CLIENT_SECRET: string;
}

declare module "*.yaml" {
  const content: string;
  export default content;
}
