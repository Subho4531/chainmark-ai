import { Hono } from "hono";
import { eq, sql } from "drizzle-orm";
import { db, sessions, merkleEvents, evidencePacks } from "../../db";
import { computeMerkleRoot } from "../crypto";
import { requireApiKey, type AppVariables } from "../middleware";

const HEX64_RE = /^[0-9a-f]{64}$/i;
const FORBIDDEN_RAW_FIELDS = ["prompt", "messages", "raw", "plaintext", "secret", "content"];

interface IngestEventInput {
  sequence: number;
  eventType: string;
  inputDigest: string;
  sanitizedDigest: string;
  policyAction: string;
  entitiesDetected?: string[];
  tokensMapped?: string[];
  eventTimestamp?: number;
  eventHash: string;
  prevHash: string;
}

export const ingestRoutes = new Hono<{ Variables: AppVariables }>();

/**
 * Receives zero-plaintext telemetry from a self-hosted local Docker chainmark-proxy
 * authenticated with a Website API Token (cm_live_...).
 */
ingestRoutes.post("/events", requireApiKey("intercept"), async (c) => {
  const { orgId } = c.get("apiKeyAuth");
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  for (const field of FORBIDDEN_RAW_FIELDS) {
    if (field in body) {
      return c.json(
        { error: `Zero-plaintext violation: raw field '${field}' is rejected by cloud ingest` },
        400
      );
    }
  }

  const sessionId = typeof body.sessionId === "string" ? body.sessionId.trim() : "";
  if (!sessionId || sessionId.length > 64) {
    return c.json({ error: "Valid sessionId (1-64 chars) is required" }, 400);
  }

  const eventsInput = Array.isArray(body.events) ? (body.events as IngestEventInput[]) : [];
  if (eventsInput.length === 0) {
    return c.json({ error: "At least one Merkle event is required" }, 400);
  }

  for (const ev of eventsInput) {
    for (const field of FORBIDDEN_RAW_FIELDS) {
      if (ev && typeof ev === "object" && field in ev) {
        return c.json(
          { error: `Zero-plaintext violation: raw field '${field}' rejected in event payload` },
          400
        );
      }
    }
    if (
      typeof ev.sequence !== "number" ||
      !Number.isInteger(ev.sequence) ||
      ev.sequence < 0 ||
      !HEX64_RE.test(ev.inputDigest || "") ||
      !HEX64_RE.test(ev.sanitizedDigest || "") ||
      !HEX64_RE.test(ev.eventHash || "") ||
      !HEX64_RE.test(ev.prevHash || "")
    ) {
      return c.json(
        {
          error:
            "Every event requires non-negative integer sequence and 64-hex digests/hashes",
        },
        400
      );
    }
  }

  const [existingSession] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.sessionId, sessionId))
    .limit(1);

  if (existingSession && existingSession.orgId && existingSession.orgId !== orgId) {
    return c.json({ error: "Session belongs to another organization" }, 403);
  }

  const now = new Date();
  const initialRoot =
    typeof body.merkleRoot === "string" && HEX64_RE.test(body.merkleRoot)
      ? body.merkleRoot.toLowerCase()
      : existingSession?.merkleRoot || computeMerkleRoot(eventsInput.map((e) => e.eventHash));

  await db.transaction(async (tx) => {
    if (!existingSession) {
      await tx.insert(sessions).values({
        sessionId,
        orgId,
        status: typeof body.status === "string" ? body.status.slice(0, 32) : "ACTIVE",
        merkleRoot: initialRoot,
        signature: typeof body.signature === "string" ? body.signature : null,
        signingPubkey: typeof body.signingPubkey === "string" ? body.signingPubkey : null,
        totalEvents: 0,
        lastActive: now,
      });
    } else if (!existingSession.orgId) {
      await tx
        .update(sessions)
        .set({ orgId, lastActive: now })
        .where(eq(sessions.sessionId, sessionId));
    }

    await tx
      .insert(merkleEvents)
      .values(
        eventsInput.map((ev) => ({
          sessionId,
          sequence: ev.sequence,
          eventType: String(ev.eventType || "egress").slice(0, 64),
          inputDigest: ev.inputDigest.toLowerCase(),
          sanitizedDigest: ev.sanitizedDigest.toLowerCase(),
          policyAction: String(ev.policyAction || "REDACT").slice(0, 64),
          entitiesDetected: Array.isArray(ev.entitiesDetected)
            ? ev.entitiesDetected.map(String)
            : [],
          tokensMapped: Array.isArray(ev.tokensMapped)
            ? ev.tokensMapped.map(String)
            : [],
          eventTimestamp:
            typeof ev.eventTimestamp === "number"
              ? ev.eventTimestamp
              : Date.now() / 1000,
          eventHash: ev.eventHash.toLowerCase(),
          prevHash: ev.prevHash.toLowerCase(),
        }))
      )
      .onConflictDoNothing({
        target: [merkleEvents.sessionId, merkleEvents.sequence],
      });

    const [countRow] = await tx
      .select({ count: sql<number>`count(*)::int` })
      .from(merkleEvents)
      .where(eq(merkleEvents.sessionId, sessionId));

    const totalEvents = countRow?.count ?? eventsInput.length;

    await tx
      .update(sessions)
      .set({
        totalEvents,
        merkleRoot: initialRoot,
        status:
          typeof body.status === "string"
            ? body.status.slice(0, 32)
            : existingSession?.status || "ACTIVE",
        signature:
          typeof body.signature === "string"
            ? body.signature
            : existingSession?.signature ?? null,
        signingPubkey:
          typeof body.signingPubkey === "string"
            ? body.signingPubkey
            : existingSession?.signingPubkey ?? null,
        lastActive: now,
      })
      .where(eq(sessions.sessionId, sessionId));
  });

  return c.json({
    accepted: eventsInput.length,
    sessionId,
    merkleRoot: initialRoot,
  });
});

ingestRoutes.post("/evidence-pack", requireApiKey("intercept"), async (c) => {
  const { orgId } = c.get("apiKeyAuth");
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  const sessionId = typeof body.sessionId === "string" ? body.sessionId.trim() : "";
  const merkleRoot = typeof body.merkleRoot === "string" ? body.merkleRoot.trim().toLowerCase() : "";
  const signature = typeof body.signature === "string" ? body.signature.trim() : "";
  const signingPubkey = typeof body.signingPubkey === "string" ? body.signingPubkey.trim() : "";
  const packBase64 = typeof body.packZipBase64 === "string" ? body.packZipBase64 : "";

  if (!sessionId || !HEX64_RE.test(merkleRoot) || !signature || !signingPubkey || !packBase64) {
    return c.json({ error: "Missing sessionId, merkleRoot, signature, signingPubkey, or packZipBase64" }, 400);
  }

  const [session] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.sessionId, sessionId))
    .limit(1);

  if (!session || session.orgId !== orgId) {
    return c.json({ error: "Session not found for this workspace" }, 404);
  }

  const packZip = Buffer.from(packBase64, "base64");
  const [inserted] = await db
    .insert(evidencePacks)
    .values({
      sessionId,
      merkleRoot,
      signature,
      signingPubkey,
      packZip,
    })
    .returning({ id: evidencePacks.id, createdAt: evidencePacks.createdAt });

  return c.json({ ok: true, packId: inserted?.id, sessionId });
});
