import crypto from "node:crypto";
import { eq, and } from "drizzle-orm";
import { db } from "./index";
import { vaultRecords } from "./schema";

// Master key from .env (64 hex characters = 32 bytes)
const MASTER_KEY_HEX =
  process.env.CHAINMARK_MASTER_KEY ||
  "50cb277ad2cb09f8a68a764f7032ae18d426c50f39277c963659d6b7f2bd17d8";
const MASTER_KEY = Buffer.from(MASTER_KEY_HEX, "hex");

export const TOKEN_REGEX = /\[CM_TOKEN_([A-Z_]+)_([a-f0-9]{32})\]/g;

/**
 * Derives a per-session 256-bit encryption key using HKDF-SHA256
 */
export function deriveSessionKey(sessionId: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      MASTER_KEY,
      Buffer.alloc(0), // no salt
      Buffer.from(`chainmark-vault-session:${sessionId}`),
      32
    )
  );
}

/**
 * Generates a deterministic typed HMAC-SHA256 token ID:
 * e.g., [CM_TOKEN_AADHAAR_9f83a...32-hex]
 */
export function generateTokenId(
  entityType: string,
  rawValue: string,
  sessionId: string
): string {
  const hmac = crypto.createHmac("sha256", MASTER_KEY);
  hmac.update(`${sessionId}:${entityType}:${rawValue}`);
  const hex = hmac.digest("hex").slice(0, 32);
  return `[CM_TOKEN_${entityType.toUpperCase()}_${hex}]`;
}

/**
 * Stores a sensitive item in the Vault:
 * 1. Derives session key via HKDF.
 * 2. Generates fresh 12-byte random IV.
 * 3. Encrypts with AES-256-GCM using sessionId as Additional Authenticated Data (AAD).
 * 4. Packs IV (12B) + Ciphertext + Auth Tag (16B) into binary Buffer.
 * 5. Persists to PostgreSQL via Drizzle ORM.
 */
export async function storeTokenizedItem(params: {
  sessionId: string;
  entityType: string;
  rawValue: string;
}): Promise<{ tokenId: string; valueDigest: string }> {
  const { sessionId, entityType, rawValue } = params;

  // SHA-256 digest of the raw value for deduplication
  const valueDigest = crypto.createHash("sha256").update(rawValue).digest("hex");
  const tokenId = generateTokenId(entityType, rawValue, sessionId);

  // Check if token already exists in PostgreSQL
  const [existing] = await db
    .select()
    .from(vaultRecords)
    .where(eq(vaultRecords.tokenId, tokenId))
    .limit(1);

  if (existing) {
    return { tokenId: existing.tokenId, valueDigest: existing.valueDigest };
  }

  // Derive session key and generate 12-byte fresh IV
  const sessionKey = deriveSessionKey(sessionId);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey, iv);
  cipher.setAAD(Buffer.from(sessionId, "utf-8")); // Bind session to prevent cross-session replay

  const ciphertext = Buffer.concat([
    cipher.update(rawValue, "utf-8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag(); // 16 bytes

  // Packed blob: [ 12-byte IV ] [ Ciphertext ] [ 16-byte Auth Tag ]
  const encryptedBlob = Buffer.concat([iv, ciphertext, authTag]);

  await db.insert(vaultRecords).values({
    tokenId,
    sessionId,
    entityType: entityType.toUpperCase(),
    encryptedBlob,
    valueDigest,
  });

  return { tokenId, valueDigest };
}

/**
 * Retrieves and detokenizes a single token from PostgreSQL using AES-256-GCM.
 * Fail-closed: returns null if auth tag or session AAD validation fails.
 */
export async function retrieveTokenizedItem(params: {
  sessionId: string;
  tokenId: string;
}): Promise<string | null> {
  const { sessionId, tokenId } = params;

  const [record] = await db
    .select()
    .from(vaultRecords)
    .where(
      and(
        eq(vaultRecords.tokenId, tokenId),
        eq(vaultRecords.sessionId, sessionId)
      )
    )
    .limit(1);

  if (!record || !record.encryptedBlob || record.encryptedBlob.length < 28) {
    return null; // 12-byte IV + 16-byte Tag = 28 bytes minimum
  }

  const blob = record.encryptedBlob;
  const iv = blob.subarray(0, 12);
  const authTag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(12, blob.length - 16);

  try {
    const sessionKey = deriveSessionKey(sessionId);
    const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey, iv);
    decipher.setAAD(Buffer.from(sessionId, "utf-8"));
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return decrypted.toString("utf-8");
  } catch {
    // Fail-closed on decryption/auth tag error
    return null;
  }
}

/**
 * Detokenizes text containing tokens back to original plaintext using PostgreSQL
 */
export async function detokenizeText(
  text: string,
  sessionId: string
): Promise<{ text: string; unresolvedCount: number }> {
  let result = text;
  let unresolvedCount = 0;
  const matches = [...text.matchAll(TOKEN_REGEX)];

  for (const match of matches) {
    const fullToken = match[0];
    const plain = await retrieveTokenizedItem({ sessionId, tokenId: fullToken });
    if (plain !== null) {
      result = result.replace(fullToken, plain);
    } else {
      unresolvedCount++;
    }
  }

  return { text: result, unresolvedCount };
}
