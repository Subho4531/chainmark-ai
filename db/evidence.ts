import crypto from "node:crypto";
import JSZip from "jszip";
import { eq, asc } from "drizzle-orm";
import { db } from "./index";
import { sessions, merkleEvents, evidencePacks } from "./schema";

export interface CanonicalEventPayload {
  sequence: number;
  eventType: string;
  inputDigest: string;
  sanitizedDigest: string;
  policyAction: string;
  prevHash: string;
  timestamp: string;
}

/**
 * Calculates SHA-256 digest of canonical JSON
 */
export function sha256Canonical(obj: unknown): string {
  const jsonStr = JSON.stringify(obj, Object.keys(obj as object).sort());
  return crypto.createHash("sha256").update(jsonStr).digest("hex");
}

/**
 * Signs data with ECDSA P-256 (SHA-256)
 */
export function signWithECDSA(data: string, privateKeyPem: string): string {
  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();
  return sign.sign(privateKeyPem, "hex");
}

/**
 * Verifies ECDSA P-256 signature
 */
export function verifyECDSASignature(
  data: string,
  signatureHex: string,
  publicKeyPem: string
): boolean {
  try {
    const verify = crypto.createVerify("SHA256");
    verify.update(data);
    verify.end();
    return verify.verify(publicKeyPem, signatureHex, "hex");
  } catch {
    return false;
  }
}

/**
 * Manages Option 2 Evidence Chains & Signed Receipts in PostgreSQL
 */
export class EvidenceService {
  private keyPair: crypto.KeyPairSyncResult<string, string>;

  constructor() {
    // Generate or load ephemeral/configured ECDSA P-256 keypair
    this.keyPair = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
  }

  public getPublicKeyPem(): string {
    return this.keyPair.publicKey;
  }

  /**
   * Initializes or gets a session in PostgreSQL
   */
  public async getOrCreateSession(sessionId: string) {
    const [existing] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.sessionId, sessionId))
      .limit(1);

    if (existing) {
      return existing;
    }

    const [created] = await db
      .insert(sessions)
      .values({
        sessionId,
        status: "ACTIVE",
        signingPubkey: this.keyPair.publicKey,
      })
      .returning();

    return created;
  }

  /**
   * Appends an event to the sequential Merkle hash chain in PostgreSQL
   */
  public async appendEvent(params: {
    sessionId: string;
    eventType: string;
    rawInput: string;
    sanitizedOutput: string;
    policyAction: string;
  }) {
    const { sessionId, eventType, rawInput, sanitizedOutput, policyAction } = params;

    // Fetch previous event to get prev_hash and next sequence
    const [prevEvent] = await db
      .select()
      .from(merkleEvents)
      .where(eq(merkleEvents.sessionId, sessionId))
      .orderBy(asc(merkleEvents.sequence))
      .limit(1);

    // Compute input/sanitized SHA-256 digests (Zero Plaintext Leakage)
    const inputDigest = crypto.createHash("sha256").update(rawInput).digest("hex");
    const sanitizedDigest = crypto.createHash("sha256").update(sanitizedOutput).digest("hex");

    // Fetch all events for sequence count
    const existingEvents = await db
      .select()
      .from(merkleEvents)
      .where(eq(merkleEvents.sessionId, sessionId))
      .orderBy(asc(merkleEvents.sequence));

    const sequence = existingEvents.length;
    const prevHash =
      sequence === 0
        ? "0000000000000000000000000000000000000000000000000000000000000000"
        : existingEvents[existingEvents.length - 1].eventHash;

    const timestamp = new Date().toISOString();

    const canonicalPayload: CanonicalEventPayload = {
      sequence,
      eventType,
      inputDigest,
      sanitizedDigest,
      policyAction,
      prevHash,
      timestamp,
    };

    const eventHash = sha256Canonical(canonicalPayload);

    const [newEvent] = await db
      .insert(merkleEvents)
      .values({
        sessionId,
        sequence,
        eventType,
        inputDigest,
        sanitizedDigest,
        policyAction,
        eventHash,
        prevHash,
      })
      .returning();

    // Update total events counter in sessions
    await db
      .update(sessions)
      .set({
        totalEvents: sequence + 1,
        lastActive: new Date(),
      })
      .where(eq(sessions.sessionId, sessionId));

    return newEvent;
  }

  /**
   * Closes a session:
   * 1. Computes the binary Merkle Root over all event hashes.
   * 2. Signs the Merkle Root with ECDSA P-256.
   * 3. Assembles sealed ZIP receipt package (chain.json, signature.sig, public_key.pem).
   * 4. Persists the signed receipt into evidence_packs table in PostgreSQL.
   */
  public async closeSessionAndSealReceipt(sessionId: string): Promise<{
    merkleRoot: string;
    signature: string;
    zipBytes: Buffer;
  }> {
    const events = await db
      .select()
      .from(merkleEvents)
      .where(eq(merkleEvents.sessionId, sessionId))
      .orderBy(asc(merkleEvents.sequence));

    if (events.length === 0) {
      throw new Error(`Session ${sessionId} has no recorded events to seal.`);
    }

    // Compute Merkle Root
    let currentLevel = events.map((e) => e.eventHash);
    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          const combined = currentLevel[i] + currentLevel[i + 1];
          nextLevel.push(crypto.createHash("sha256").update(combined).digest("hex"));
        } else {
          nextLevel.push(currentLevel[i]);
        }
      }
      currentLevel = nextLevel;
    }
    const merkleRoot = currentLevel[0];

    // Sign the 32-byte Merkle root using ECDSA P-256
    const signature = signWithECDSA(merkleRoot, this.keyPair.privateKey);

    // Build the downloadable ZIP evidence receipt package
    const zip = new JSZip();
    zip.file(
      "chain.json",
      JSON.stringify(
        {
          sessionId,
          totalEvents: events.length,
          merkleRoot,
          events,
        },
        null,
        2
      )
    );
    zip.file("signature.sig", signature);
    zip.file("public_key.pem", this.keyPair.publicKey);

    const zipBytes = await zip.generateAsync({ type: "nodebuffer" });

    // Persist into evidence_packs and update session in PostgreSQL
    await db.insert(evidencePacks).values({
      sessionId,
      merkleRoot,
      signature,
      signingPubkey: this.keyPair.publicKey,
      packZip: zipBytes,
    });

    await db
      .update(sessions)
      .set({
        status: "CLOSED",
        merkleRoot,
        signature,
        lastActive: new Date(),
      })
      .where(eq(sessions.sessionId, sessionId));

    return { merkleRoot, signature, zipBytes };
  }

  /**
   * Verifies an offline ZIP receipt package:
   * Asserts ECDSA P-256 signature and recalculates unbroken SHA-256 Merkle chain.
   */
  public async verifyReceiptPack(zipBuffer: Buffer): Promise<{
    verified: boolean;
    merkleRoot: string;
    totalEvents: number;
    error?: string;
  }> {
    try {
      const zip = await JSZip.loadAsync(zipBuffer);
      const chainFile = zip.file("chain.json");
      const sigFile = zip.file("signature.sig");
      const pubFile = zip.file("public_key.pem");

      if (!chainFile || !sigFile || !pubFile) {
        return {
          verified: false,
          merkleRoot: "",
          totalEvents: 0,
          error: "Receipt ZIP is missing required cryptographic files",
        };
      }

      const chainData = JSON.parse(await chainFile.async("string"));
      const signature = (await sigFile.async("string")).trim();
      const publicKey = await pubFile.async("string");

      // 1. Verify ECDSA signature against Merkle root
      const sigValid = verifyECDSASignature(chainData.merkleRoot, signature, publicKey);
      if (!sigValid) {
        return {
          verified: false,
          merkleRoot: chainData.merkleRoot,
          totalEvents: chainData.events.length,
          error: "ECDSA P-256 signature is INVALID",
        };
      }

      // 2. Verify sequential hash chain
      let prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
      for (const event of chainData.events) {
        if (event.prevHash !== prevHash) {
          return {
            verified: false,
            merkleRoot: chainData.merkleRoot,
            totalEvents: chainData.events.length,
            error: `Hash chain broken at sequence ${event.sequence}`,
          };
        }
        prevHash = event.eventHash;
      }

      return {
        verified: true,
        merkleRoot: chainData.merkleRoot,
        totalEvents: chainData.events.length,
      };
    } catch (e) {
      return {
        verified: false,
        merkleRoot: "",
        totalEvents: 0,
        error: `Corrupt ZIP package: ${e}`,
      };
    }
  }
}
