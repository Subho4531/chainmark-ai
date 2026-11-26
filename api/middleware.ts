import { createMiddleware } from "hono/factory";
import { getCookie } from "hono/cookie";
import { eq } from "drizzle-orm";
import { db, apiKeys } from "../db";
import { hashApiKey, verifySessionJwt } from "./crypto";

export const SESSION_COOKIE_NAME = "cm_session";

export interface AuthContext {
  userId: string;
  orgId: string;
  role: string;
  email: string;
}

export interface ApiKeyContext {
  keyId: string;
  orgId: string;
  scopes: string[];
  prefix: string;
}

export type AppVariables = {
  auth: AuthContext;
  apiKeyAuth: ApiKeyContext;
};

/**
 * Authenticates web portal requests via HttpOnly session cookie or Bearer JWT.
 */
export const requireSession = createMiddleware<{ Variables: AppVariables }>(
  async (c, next) => {
    const cookieToken = getCookie(c, SESSION_COOKIE_NAME);
    const authHeader = c.req.header("authorization");
    const headerToken = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : undefined;

    const token = cookieToken || headerToken;
    if (!token) {
      return c.json({ error: "Authentication required" }, 401);
    }

    const claims = verifySessionJwt(token);
    if (!claims) {
      return c.json({ error: "Invalid or expired session" }, 401);
    }

    c.set("auth", {
      userId: claims.sub,
      orgId: claims.orgId,
      role: claims.role,
      email: claims.email,
    });
    await next();
  }
);

/**
 * Authenticates telemetry ingestion from local Docker chainmark-proxy containers
 * using Website API Tokens (cm_live_...) validated via HMAC-SHA256 hash lookup.
 */
export function requireApiKey(requiredScope: string) {
  return createMiddleware<{ Variables: AppVariables }>(async (c, next) => {
    const authHeader = c.req.header("authorization");
    const customHeader = c.req.header("x-chainmark-api-key");
    const rawToken = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : customHeader?.trim();

    if (!rawToken || !rawToken.startsWith("cm_live_")) {
      return c.json({ error: "Missing or malformed Chainmark API token" }, 401);
    }

    const keyHash = hashApiKey(rawToken);
    const [keyRecord] = await db
      .select()
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, keyHash))
      .limit(1);

    if (!keyRecord || keyRecord.status !== "active") {
      return c.json({ error: "Invalid or revoked API token" }, 401);
    }

    if (!keyRecord.scopes.includes(requiredScope) && !keyRecord.scopes.includes("admin")) {
      return c.json(
        { error: `API token lacks required '${requiredScope}' scope` },
        403
      );
    }

    // Touch lastUsedAt asynchronously without blocking ingestion path
    db.update(apiKeys)
      .set({ lastUsedAt: new Date() })
      .where(eq(apiKeys.id, keyRecord.id))
      .catch(() => {});

    c.set("apiKeyAuth", {
      keyId: keyRecord.id,
      orgId: keyRecord.orgId,
      scopes: keyRecord.scopes,
      prefix: keyRecord.prefix,
    });
    await next();
  });
}
