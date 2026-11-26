import crypto from "node:crypto";
import { Hono } from "hono";
import { setCookie, deleteCookie } from "hono/cookie";
import { eq, sql } from "drizzle-orm";
import { db, users, organizations, orgMembers, sessions, merkleEvents, evidencePacks } from "../../db";
import { hashPassword, verifyPassword, signSessionJwt, slugifyWorkspace } from "../crypto";
import { requireSession, SESSION_COOKIE_NAME, type AppVariables } from "../middleware";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function setSessionCookie(c: Parameters<typeof setCookie>[0], token: string) {
  setCookie(c, SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
    secure: process.env.NODE_ENV === "production",
  });
}

export const authRoutes = new Hono<{ Variables: AppVariables }>();

authRoutes.post("/signup", async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return c.json({ error: "Invalid JSON payload" }, 400);
  }

  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const rawName = typeof body.name === "string" ? body.name.trim() : "";
  const rawWorkspace = typeof body.workspaceName === "string" ? body.workspaceName.trim() : "";

  if (!EMAIL_RE.test(email)) {
    return c.json({ error: "Enter a valid email address" }, 400);
  }
  if (password.length < 8) {
    return c.json({ error: "Password must be at least 8 characters" }, 400);
  }

  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (existing) {
    return c.json({ error: "An account with that email already exists" }, 409);
  }

  const displayName = rawName || email.split("@")[0] || "Operator";
  const orgName = rawWorkspace || `${displayName}'s Workspace`;
  const userId = `usr_${crypto.randomBytes(8).toString("hex")}`;
  const orgId = `org_${crypto.randomBytes(8).toString("hex")}`;
  const baseSlug = slugifyWorkspace(orgName);
  const slug = `${baseSlug}-${crypto.randomBytes(2).toString("hex")}`;
  const passwordHash = hashPassword(password);

  await db.transaction(async (tx) => {
    await tx.insert(users).values({
      id: userId,
      email,
      name: displayName,
      passwordHash,
    });
    await tx.insert(organizations).values({
      id: orgId,
      name: orgName,
      slug,
      plan: "cloud_usage",
    });
    await tx.insert(orgMembers).values({
      orgId,
      userId,
      role: "owner",
    });
  });

  const token = signSessionJwt({ sub: userId, orgId, role: "owner", email });
  setSessionCookie(c, token);

  return c.json(
    {
      user: { id: userId, email, name: displayName },
      org: { id: orgId, name: orgName, slug, plan: "cloud_usage", role: "owner" },
    },
    201
  );
});

authRoutes.post("/login", async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return c.json({ error: "Invalid JSON payload" }, 400);
  }

  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (!user || !verifyPassword(password, user.passwordHash)) {
    return c.json({ error: "Invalid email or password" }, 401);
  }

  const [membership] = await db
    .select({
      orgId: organizations.id,
      orgName: organizations.name,
      orgSlug: organizations.slug,
      orgPlan: organizations.plan,
      role: orgMembers.role,
    })
    .from(orgMembers)
    .innerJoin(organizations, eq(orgMembers.orgId, organizations.id))
    .where(eq(orgMembers.userId, user.id))
    .limit(1);

  if (!membership) {
    return c.json({ error: "No workspace found for this account" }, 403);
  }

  const token = signSessionJwt({
    sub: user.id,
    orgId: membership.orgId,
    role: membership.role,
    email: user.email,
  });
  setSessionCookie(c, token);

  return c.json({
    user: { id: user.id, email: user.email, name: user.name },
    org: {
      id: membership.orgId,
      name: membership.orgName,
      slug: membership.orgSlug,
      plan: membership.orgPlan,
      role: membership.role,
    },
  });
});

authRoutes.post("/logout", (c) => {
  deleteCookie(c, SESSION_COOKIE_NAME, { path: "/" });
  return c.json({ ok: true });
});

authRoutes.get("/me", requireSession, async (c) => {
  const auth = c.get("auth");

  const [user] = await db
    .select({ id: users.id, email: users.email, name: users.name, createdAt: users.createdAt })
    .from(users)
    .where(eq(users.id, auth.userId))
    .limit(1);

  const [org] = await db
    .select()
    .from(organizations)
    .where(eq(organizations.id, auth.orgId))
    .limit(1);

  if (!user || !org) {
    return c.json({ error: "Account or workspace no longer exists" }, 401);
  }

  const [usageStats] = await db
    .select({
      totalSessions: sql<number>`count(distinct ${sessions.sessionId})::int`,
      totalEvents: sql<number>`coalesce(sum(${sessions.totalEvents}), 0)::int`,
    })
    .from(sessions)
    .where(eq(sessions.orgId, org.id));

  const [eventBytesRow] = await db
    .select({
      eventsCount: sql<number>`count(*)::int`,
    })
    .from(merkleEvents)
    .innerJoin(sessions, eq(merkleEvents.sessionId, sessions.sessionId))
    .where(eq(sessions.orgId, org.id));

  const [packRow] = await db
    .select({
      packsCount: sql<number>`count(*)::int`,
      packsBytes: sql<number>`coalesce(sum(octet_length(${evidencePacks.packZip})), 0)::int`,
    })
    .from(evidencePacks)
    .innerJoin(sessions, eq(evidencePacks.sessionId, sessions.sessionId))
    .where(eq(sessions.orgId, org.id));

  const eventsCount = eventBytesRow?.eventsCount ?? 0;
  const packsBytes = packRow?.packsBytes ?? 0;
  // ~512 bytes average structured ledger row + compressed evidence packs
  const estimatedAuditBytes = eventsCount * 512 + packsBytes;

  return c.json({
    user,
    org: {
      id: org.id,
      name: org.name,
      slug: org.slug,
      plan: org.plan,
      role: auth.role,
    },
    billing: {
      mode: process.env.DEPLOYMENT_MODE || "cloud",
      sessionsCount: usageStats?.totalSessions ?? 0,
      eventsStored: eventsCount,
      packsStored: packRow?.packsCount ?? 0,
      estimatedAuditBytes,
    },
  });
});
