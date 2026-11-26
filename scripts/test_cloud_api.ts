import crypto from "node:crypto";
import JSZip from "jszip";
import { afterAll, describe, expect, it } from "bun:test";
import { inArray } from "drizzle-orm";
import { db, organizations, sessions, users } from "../db";
import { createCloudApp } from "../api/app";
import { computeMerkleRoot } from "../api/crypto";

const GENESIS = "0000000000000000000000000000000000000000000000000000000000000000";

function sha256Hex(val: string): string {
  return crypto.createHash("sha256").update(val).digest("hex");
}

function extractCookie(setCookieHeader: string | null): string {
  expect(setCookieHeader).toBeTruthy();
  return (setCookieHeader || "").split(";")[0]!;
}

describe("Managed Cloud Hono API (Option 2)", () => {
  const app = createCloudApp();
  const suffix = crypto.randomBytes(4).toString("hex");
  const emailA = `alice-${suffix}@example.com`;
  const emailB = `bob-${suffix}@example.com`;
  const createdUserIds: string[] = [];
  const createdOrgIds: string[] = [];
  const createdSessionIds: string[] = [];

  afterAll(async () => {
    if (createdSessionIds.length > 0) {
      await db.delete(sessions).where(inArray(sessions.sessionId, createdSessionIds));
    }
    if (createdOrgIds.length > 0) {
      await db.delete(organizations).where(inArray(organizations.id, createdOrgIds));
    }
    if (createdUserIds.length > 0) {
      await db.delete(users).where(inArray(users.id, createdUserIds));
    }
  });

  it("supports signup, duplicate rejection, login, API keys, zero-plaintext ingest, org isolation, verify & zip export", async () => {
    // 1. Signup User A
    const signupRes = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: emailA,
        password: "super-secure-password",
        name: "Alice Ops",
        workspaceName: `Acme Cloud ${suffix}`,
      }),
    });
    expect(signupRes.status).toBe(201);
    const signupBody = await signupRes.json();
    createdUserIds.push(signupBody.user.id);
    createdOrgIds.push(signupBody.org.id);
    const cookieA = extractCookie(signupRes.headers.get("set-cookie"));

    // 2. Reject duplicate signup
    const dupRes = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: emailA,
        password: "super-secure-password",
      }),
    });
    expect(dupRes.status).toBe(409);

    // 3. Protected endpoint rejects anonymous access, accepts login cookie
    const anonMe = await app.request("/api/auth/me");
    expect(anonMe.status).toBe(401);

    const loginRes = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: emailA,
        password: "super-secure-password",
      }),
    });
    expect(loginRes.status).toBe(200);
    const loginCookie = extractCookie(loginRes.headers.get("set-cookie"));

    const meRes = await app.request("/api/auth/me", {
      headers: { Cookie: loginCookie || cookieA },
    });
    expect(meRes.status).toBe(200);
    const meData = await meRes.json();
    expect(meData.user.email).toBe(emailA);
    expect(meData.org.id).toBe(signupBody.org.id);

    // 4. Create Website API key (cm_live_...)
    const createKeyRes = await app.request("/api/keys", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: loginCookie,
      },
      body: JSON.stringify({ name: "docker-prod", scopes: ["intercept", "verify"] }),
    });
    expect(createKeyRes.status).toBe(201);
    const keyPayload = await createKeyRes.json();
    expect(keyPayload.secret).toStartWith("cm_live_");
    const firstSecret: string = keyPayload.secret;
    const keyId: string = keyPayload.key.id;

    // 5. Zero-plaintext enforcement rejects raw prompt payload
    const badIngest = await app.request("/api/ingest/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${firstSecret}`,
      },
      body: JSON.stringify({
        sessionId: `sess-bad-${suffix}`,
        prompt: "My SSN is 123-45-6789",
        events: [],
      }),
    });
    expect(badIngest.status).toBe(400);

    // 6. Valid signed Merkle events ingested via cm_live_... token
    const kp = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const ev0Hash = sha256Hex(`ev0-${suffix}`);
    const ev1Hash = sha256Hex(`ev1-${suffix}`);
    const merkleRoot = computeMerkleRoot([ev0Hash, ev1Hash]);
    const signer = crypto.createSign("SHA256");
    signer.update(merkleRoot);
    signer.end();
    const sigBase64 = signer.sign(kp.privateKey, "base64");

    const sessionId = `agent-cloud-${suffix}`;
    createdSessionIds.push(sessionId);

    const okIngest = await app.request("/api/ingest/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${firstSecret}`,
      },
      body: JSON.stringify({
        sessionId,
        merkleRoot,
        signature: sigBase64,
        signingPubkey: kp.publicKey,
        status: "SEALED",
        events: [
          {
            sequence: 0,
            eventType: "egress_sanitized",
            inputDigest: sha256Hex("in-0"),
            sanitizedDigest: sha256Hex("out-0"),
            policyAction: "REDACT",
            entitiesDetected: ["AADHAAR", "CREDIT_CARD"],
            tokensMapped: ["<TKN_1111>", "<TKN_2222>"],
            eventTimestamp: Date.now() / 1000,
            eventHash: ev0Hash,
            prevHash: GENESIS,
          },
          {
            sequence: 1,
            eventType: "ingress_detokenized",
            inputDigest: sha256Hex("in-1"),
            sanitizedDigest: sha256Hex("out-1"),
            policyAction: "DETOKENIZE",
            entitiesDetected: [],
            tokensMapped: ["<TKN_1111>"],
            eventTimestamp: Date.now() / 1000,
            eventHash: ev1Hash,
            prevHash: ev0Hash,
          },
        ],
      }),
    });
    expect(okIngest.status).toBe(200);
    const ingestJson = await okIngest.json();
    expect(ingestJson.accepted).toBe(2);

    // 7. Analytics overview & cryptographic verification & .zip export
    const overviewRes = await app.request("/api/analytics/overview?range=24h", {
      headers: { Cookie: loginCookie },
    });
    expect(overviewRes.status).toBe(200);
    const overview = await overviewRes.json();
    expect(overview.summary.totalSessions).toBe(1);
    expect(overview.summary.totalEventsStored).toBe(2);
    expect(overview.summary.tokensRedacted).toBe(3);

    const verifyRes = await app.request(`/api/analytics/sessions/${sessionId}/verify`, {
      headers: { Cookie: loginCookie },
    });
    expect(verifyRes.status).toBe(200);
    const verifyData = await verifyRes.json();
    expect(verifyData.valid).toBe(true);
    expect(verifyData.signatureValid).toBe(true);
    expect(verifyData.rootMatches).toBe(true);

    const zipRes = await app.request(`/api/analytics/sessions/${sessionId}/export`, {
      headers: { Cookie: loginCookie },
    });
    expect(zipRes.status).toBe(200);
    const zipBytes = new Uint8Array(await zipRes.arrayBuffer());
    const zip = await JSZip.loadAsync(zipBytes);
    expect(zip.file("chain.json")).toBeTruthy();
    expect(zip.file("signature.sig")).toBeTruthy();
    expect(zip.file("public_key.pem")).toBeTruthy();

    // 8. Org isolation: User B cannot view/verify/export User A's session
    const signupB = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: emailB,
        password: "other-secure-password",
        name: "Bob Audit",
        workspaceName: `Bob Org ${suffix}`,
      }),
    });
    expect(signupB.status).toBe(201);
    const signupBData = await signupB.json();
    createdUserIds.push(signupBData.user.id);
    createdOrgIds.push(signupBData.org.id);
    const cookieB = extractCookie(signupB.headers.get("set-cookie"));

    const crossVerify = await app.request(`/api/analytics/sessions/${sessionId}/verify`, {
      headers: { Cookie: cookieB },
    });
    expect(crossVerify.status).toBe(404);

    // 9. Key rotation & revocation invalidates old secret
    const rotateRes = await app.request(`/api/keys/${keyId}/rotate`, {
      method: "POST",
      headers: { Cookie: loginCookie },
    });
    expect(rotateRes.status).toBe(200);

    const staleIngest = await app.request("/api/ingest/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${firstSecret}`,
      },
      body: JSON.stringify({ sessionId, events: [] }),
    });
    expect(staleIngest.status).toBe(401);

    const revokeRes = await app.request(`/api/keys/${keyId}`, {
      method: "DELETE",
      headers: { Cookie: loginCookie },
    });
    expect(revokeRes.status).toBe(200);
  });
});
