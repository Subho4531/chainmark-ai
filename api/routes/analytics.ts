import { Hono } from "hono";
import JSZip from "jszip";
import { and, asc, desc, eq, gte, inArray } from "drizzle-orm";
import { db, sessions, merkleEvents, evidencePacks } from "../../db";
import { computeMerkleRoot, verifyEcdsaP256 } from "../crypto";
import { requireSession, type AppVariables } from "../middleware";

const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

function rangeStartDate(range: string): Date {
  const now = Date.now();
  if (range === "7d") return new Date(now - 7 * 24 * 60 * 60 * 1000);
  if (range === "30d") return new Date(now - 30 * 24 * 60 * 60 * 1000);
  return new Date(now - 24 * 60 * 60 * 1000);
}

export const analyticsRoutes = new Hono<{ Variables: AppVariables }>();

analyticsRoutes.use("*", requireSession);

analyticsRoutes.get("/overview", async (c) => {
  const auth = c.get("auth");
  const range = c.req.query("range") || "24h";
  const since = rangeStartDate(range);

  const orgSessions = await db
    .select()
    .from(sessions)
    .where(eq(sessions.orgId, auth.orgId))
    .orderBy(desc(sessions.lastActive))
    .limit(50);

  const sessionIds = orgSessions.map((s) => s.sessionId);

  const allEvents =
    sessionIds.length > 0
      ? await db
          .select()
          .from(merkleEvents)
          .where(and(inArray(merkleEvents.sessionId, sessionIds), gte(merkleEvents.createdAt, since)))
          .orderBy(desc(merkleEvents.createdAt))
          .limit(500)
      : [];

  const packs =
    sessionIds.length > 0
      ? await db
          .select({
            id: evidencePacks.id,
            sessionId: evidencePacks.sessionId,
            sizeBytes: evidencePacks.packZip,
            createdAt: evidencePacks.createdAt,
          })
          .from(evidencePacks)
          .where(inArray(evidencePacks.sessionId, sessionIds))
      : [];

  // Aggregate detector counts and tokens mapped
  const detectorCounts = new Map<string, number>();
  let totalTokensMapped = 0;
  let totalBlocks = 0;

  for (const ev of allEvents) {
    totalTokensMapped += ev.tokensMapped.length;
    if (ev.policyAction.toUpperCase().includes("BLOCK")) {
      totalBlocks += 1;
    }
    for (const ent of ev.entitiesDetected) {
      detectorCounts.set(ent, (detectorCounts.get(ent) ?? 0) + 1);
    }
  }

  const maxDetectorCount = Math.max(1, ...detectorCounts.values());
  const detectors = Array.from(detectorCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({
      name,
      count,
      share: Math.round((count / maxDetectorCount) * 100),
    }));

  // Bucket throughput across 12 slots for the selected time window
  const bucketCount = 12;
  const windowMs = Date.now() - since.getTime();
  const series = new Array<number>(bucketCount).fill(0);
  for (const ev of allEvents) {
    const offset = ev.createdAt.getTime() - since.getTime();
    const idx = Math.min(
      bucketCount - 1,
      Math.max(0, Math.floor((offset / Math.max(1, windowMs)) * bucketCount))
    );
    series[idx] = (series[idx] ?? 0) + 1;
  }

  const packSessionSet = new Set(packs.map((p) => p.sessionId));
  const packsBytes = packs.reduce((sum, p) => sum + (p.sizeBytes?.length ?? 0), 0);
  const totalEventsStored = orgSessions.reduce((sum, s) => sum + s.totalEvents, 0);
  const estimatedAuditBytes = totalEventsStored * 512 + packsBytes;

  const latestSession = orgSessions[0] ?? null;
  const recentSessions = orgSessions.slice(0, 10).map((s) => ({
    sessionId: s.sessionId,
    status: s.status,
    totalEvents: s.totalEvents,
    merkleRoot: s.merkleRoot,
    hasSignature: Boolean(s.signature),
    hasPack: packSessionSet.has(s.sessionId),
    createdAt: s.createdAt.toISOString(),
    lastActive: s.lastActive.toISOString(),
  }));

  const latestEvents = allEvents.slice(0, 12).map((ev) => ({
    id: ev.id,
    sessionId: ev.sessionId,
    sequence: ev.sequence,
    eventType: ev.eventType,
    policyAction: ev.policyAction,
    entitiesDetected: ev.entitiesDetected,
    tokenCount: ev.tokensMapped.length,
    inputDigest: ev.inputDigest,
    eventHash: ev.eventHash,
    createdAt: ev.createdAt.toISOString(),
  }));

  return c.json({
    range,
    summary: {
      totalSessions: orgSessions.length,
      eventsInWindow: allEvents.length,
      totalEventsStored,
      tokensRedacted: totalTokensMapped,
      blockedCalls: totalBlocks,
      estimatedAuditBytes,
      packsStored: packs.length,
    },
    series,
    detectors,
    sessions: recentSessions,
    latestEvents,
    chainHead: latestSession
      ? {
          sessionId: latestSession.sessionId,
          merkleRoot: latestSession.merkleRoot,
          totalEvents: latestSession.totalEvents,
          signatureValid: Boolean(latestSession.signature),
          status: latestSession.status,
        }
      : null,
  });
});

analyticsRoutes.get("/sessions", async (c) => {
  const auth = c.get("auth");
  const rows = await db
    .select()
    .from(sessions)
    .where(eq(sessions.orgId, auth.orgId))
    .orderBy(desc(sessions.lastActive))
    .limit(100);

  return c.json({ sessions: rows });
});

analyticsRoutes.get("/sessions/:sessionId/verify", async (c) => {
  const auth = c.get("auth");
  const sessionId = c.req.param("sessionId");

  const [session] = await db
    .select()
    .from(sessions)
    .where(and(eq(sessions.sessionId, sessionId), eq(sessions.orgId, auth.orgId)))
    .limit(1);

  if (!session) {
    return c.json({ error: "Session not found" }, 404);
  }

  const events = await db
    .select()
    .from(merkleEvents)
    .where(eq(merkleEvents.sessionId, sessionId))
    .orderBy(asc(merkleEvents.sequence));

  let prevHash = GENESIS_HASH;
  let sequenceContinuous = true;
  let hashChainValid = true;
  let failureReason: string | null = null;

  for (let i = 0; i < events.length; i++) {
    const ev = events[i]!;
    if (ev.sequence !== i) {
      sequenceContinuous = false;
      failureReason = `Sequence gap at index ${i}: expected ${i}, got ${ev.sequence}`;
      break;
    }
    if (ev.prevHash !== prevHash) {
      hashChainValid = false;
      failureReason = `Broken prev_hash link at sequence ${i}`;
      break;
    }
    prevHash = ev.eventHash;
  }

  const computedRoot = computeMerkleRoot(events.map((e) => e.eventHash));
  const rootMatches =
    events.length === 0 ? true : computedRoot === session.merkleRoot;

  let signatureValid: boolean | null = null;
  if (session.signature && session.signingPubkey) {
    signatureValid = verifyEcdsaP256(
      session.merkleRoot,
      session.signature,
      session.signingPubkey
    );
  }

  const valid =
    sequenceContinuous &&
    hashChainValid &&
    rootMatches &&
    (signatureValid === null || signatureValid === true);

  return c.json({
    sessionId,
    valid,
    checkedEvents: events.length,
    sequenceContinuous,
    hashChainValid,
    rootMatches,
    signatureValid,
    merkleRoot: session.merkleRoot,
    computedRoot,
    failureReason,
  });
});

analyticsRoutes.get("/sessions/:sessionId/export", async (c) => {
  const auth = c.get("auth");
  const sessionId = c.req.param("sessionId");

  const [session] = await db
    .select()
    .from(sessions)
    .where(and(eq(sessions.sessionId, sessionId), eq(sessions.orgId, auth.orgId)))
    .limit(1);

  if (!session) {
    return c.json({ error: "Session not found" }, 404);
  }

  // Return pre-sealed pack from PostgreSQL if present
  const [storedPack] = await db
    .select()
    .from(evidencePacks)
    .where(eq(evidencePacks.sessionId, sessionId))
    .orderBy(desc(evidencePacks.createdAt))
    .limit(1);

  if (storedPack?.packZip) {
    return new Response(new Uint8Array(storedPack.packZip), {
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": `attachment; filename="evidence_pack_${sessionId}.zip"`,
      },
    });
  }

  // Otherwise construct portable receipt ZIP from recorded Merkle events
  const events = await db
    .select()
    .from(merkleEvents)
    .where(eq(merkleEvents.sessionId, sessionId))
    .orderBy(asc(merkleEvents.sequence));

  const zip = new JSZip();
  zip.file(
    "chain.json",
    JSON.stringify(
      {
        session_id: session.sessionId,
        merkle_root: session.merkleRoot,
        total_events: events.length,
        events: events.map((ev) => ({
          sequence: ev.sequence,
          timestamp: ev.eventTimestamp,
          session_id: ev.sessionId,
          event_type: ev.eventType,
          input_digest: ev.inputDigest,
          sanitized_digest: ev.sanitizedDigest,
          entities_detected: ev.entitiesDetected,
          tokens_mapped: ev.tokensMapped,
          policy_action: ev.policyAction,
          prev_hash: ev.prevHash,
          node_hash: ev.eventHash,
        })),
      },
      null,
      2
    )
  );

  if (session.signature) {
    zip.file("signature.sig", session.signature);
  }
  if (session.signingPubkey) {
    zip.file("public_key.pem", session.signingPubkey);
  }

  const zipBuffer = await zip.generateAsync({ type: "uint8array" });

  return new Response(zipBuffer, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="evidence_pack_${sessionId}.zip"`,
    },
  });
});
