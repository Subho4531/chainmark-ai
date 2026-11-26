import crypto from "node:crypto";
import { Hono } from "hono";
import { and, desc, eq } from "drizzle-orm";
import { db, apiKeys } from "../../db";
import { generateApiKeySecret } from "../crypto";
import { requireSession, type AppVariables } from "../middleware";

const ALLOWED_SCOPES = new Set(["intercept", "vault", "verify", "admin"]);

function sanitizeScopes(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return ["intercept"];
  }
  const filtered = input.filter(
    (item): item is string => typeof item === "string" && ALLOWED_SCOPES.has(item)
  );
  return filtered.length > 0 ? Array.from(new Set(filtered)) : ["intercept"];
}

export const keysRoutes = new Hono<{ Variables: AppVariables }>();

keysRoutes.use("*", requireSession);

keysRoutes.get("/", async (c) => {
  const auth = c.get("auth");
  const rows = await db
    .select({
      id: apiKeys.id,
      name: apiKeys.name,
      prefix: apiKeys.prefix,
      scopes: apiKeys.scopes,
      status: apiKeys.status,
      lastUsedAt: apiKeys.lastUsedAt,
      createdAt: apiKeys.createdAt,
    })
    .from(apiKeys)
    .where(eq(apiKeys.orgId, auth.orgId))
    .orderBy(desc(apiKeys.createdAt));

  return c.json({ keys: rows });
});

keysRoutes.post("/", async (c) => {
  const auth = c.get("auth");
  const body = await c.req.json().catch(() => ({}));
  const name =
    typeof body.name === "string" && body.name.trim()
      ? body.name.trim().slice(0, 120)
      : "agent-runtime";
  const scopes = sanitizeScopes(body.scopes);

  const id = `k_${crypto.randomBytes(8).toString("hex")}`;
  const { secret, prefix, keyHash } = generateApiKeySecret();

  const [created] = await db
    .insert(apiKeys)
    .values({
      id,
      orgId: auth.orgId,
      createdByUserId: auth.userId,
      name,
      prefix,
      keyHash,
      scopes,
      status: "active",
    })
    .returning({
      id: apiKeys.id,
      name: apiKeys.name,
      prefix: apiKeys.prefix,
      scopes: apiKeys.scopes,
      status: apiKeys.status,
      lastUsedAt: apiKeys.lastUsedAt,
      createdAt: apiKeys.createdAt,
    });

  return c.json({ key: created, secret }, 201);
});

keysRoutes.post("/:id/rotate", async (c) => {
  const auth = c.get("auth");
  const id = c.req.param("id");

  const [existing] = await db
    .select()
    .from(apiKeys)
    .where(and(eq(apiKeys.id, id), eq(apiKeys.orgId, auth.orgId)))
    .limit(1);

  if (!existing) {
    return c.json({ error: "API key not found" }, 404);
  }
  if (existing.status === "revoked") {
    return c.json({ error: "Cannot rotate a revoked API key" }, 400);
  }

  const { secret, prefix, keyHash } = generateApiKeySecret();

  const [updated] = await db
    .update(apiKeys)
    .set({
      prefix,
      keyHash,
      lastUsedAt: null,
      status: "active",
    })
    .where(and(eq(apiKeys.id, id), eq(apiKeys.orgId, auth.orgId)))
    .returning({
      id: apiKeys.id,
      name: apiKeys.name,
      prefix: apiKeys.prefix,
      scopes: apiKeys.scopes,
      status: apiKeys.status,
      lastUsedAt: apiKeys.lastUsedAt,
      createdAt: apiKeys.createdAt,
    });

  return c.json({ key: updated, secret });
});

keysRoutes.delete("/:id", async (c) => {
  const auth = c.get("auth");
  const id = c.req.param("id");

  const [revoked] = await db
    .update(apiKeys)
    .set({ status: "revoked" })
    .where(and(eq(apiKeys.id, id), eq(apiKeys.orgId, auth.orgId)))
    .returning({ id: apiKeys.id, status: apiKeys.status });

  if (!revoked) {
    return c.json({ error: "API key not found" }, 404);
  }

  return c.json({ ok: true, id: revoked.id, status: revoked.status });
});
