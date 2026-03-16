/**
 * Auth client for checking tool-level authorization against the centralized auth service.
 * Also fetches per-user credentials from the auth service.
 */

export interface AuthEnv {
  AUTH_URL: string;
  AUTH_SECRET: string;
}

export interface AuthCheckResult {
  allowed: boolean;
  reason: string;
}

/**
 * Check if a user is allowed to use a specific tool on a service.
 */
export async function checkAuth(
  env: AuthEnv,
  email: string,
  service: string,
  tool: string,
): Promise<boolean> {
  try {
    const res = await fetch(`${env.AUTH_URL}/check`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Auth-Secret": env.AUTH_SECRET,
      },
      body: JSON.stringify({ email, service, tool }),
    });

    if (!res.ok) return false;

    const result = (await res.json()) as AuthCheckResult;
    return result.allowed;
  } catch {
    // Auth service unavailable — fail open for now
    return true;
  }
}

/**
 * Fetch per-user credentials from the auth service.
 */
export async function fetchUserCredentials<T extends Record<string, string> = Record<string, string>>(
  env: AuthEnv,
  email: string,
  service: string,
): Promise<T | null> {
  try {
    const res = await fetch(`${env.AUTH_URL}/credentials/${encodeURIComponent(email)}/${encodeURIComponent(service)}`, {
      headers: { "X-Auth-Secret": env.AUTH_SECRET },
    });

    if (!res.ok) return null;

    const data = (await res.json()) as { credentials: T | null };
    return data.credentials;
  } catch {
    return null;
  }
}
