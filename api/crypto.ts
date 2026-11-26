import crypto from "node:crypto";

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export interface SessionJwtPayload {
  sub: string;
  orgId: string;
  role: string;
  email: string;
  iat: number;
  exp: number;
}

/**
 * Resolves the HMAC signing secret for JWT session cookies and API key hashes.
 * Reads AUTH_SECRET from env, falling back to a keyed derivative of CHAINMARK_MASTER_KEY in local dev.
 */
export function getAuthSecret(): string {
  const configured = process.env.AUTH_SECRET?.trim();
  if (configured && configured.length >= 16) {
    return configured;
  }
  const masterKey = process.env.CHAINMARK_MASTER_KEY?.trim();
  if (masterKey) {
    return crypto
      .createHmac("sha256", masterKey)
      .update("chainmark-cloud-auth-derived-v1")
      .digest("hex");
  }
  throw new Error("AUTH_SECRET (or CHAINMARK_MASTER_KEY fallback) must be configured");
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }
  const [, salt, expectedHex] = parts;
  if (!salt || !expectedHex) {
    return false;
  }
  try {
    const derived = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(expectedHex, "hex");
    if (derived.length !== expected.length) {
      return false;
    }
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

export function hashApiKey(secret: string): string {
  return crypto.createHmac("sha256", getAuthSecret()).update(secret).digest("hex");
}

export function generateApiKeySecret(): {
  secret: string;
  prefix: string;
  keyHash: string;
} {
  const randomHex = crypto.randomBytes(16).toString("hex");
  const secret = `cm_live_${randomHex}`;
  const prefix = secret.slice(0, 12);
  const keyHash = hashApiKey(secret);
  return { secret, prefix, keyHash };
}

export function signSessionJwt(claims: Omit<SessionJwtPayload, "iat" | "exp">): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionJwtPayload = {
    ...claims,
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
  };
  const headerB64 = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString(
    "base64url"
  );
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signingInput = `${headerB64}.${payloadB64}`;
  const sigB64 = crypto
    .createHmac("sha256", getAuthSecret())
    .update(signingInput)
    .digest("base64url");
  return `${signingInput}.${sigB64}`;
}

export function verifySessionJwt(token: string): SessionJwtPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const [headerB64, payloadB64, sigB64] = parts;
  if (!headerB64 || !payloadB64 || !sigB64) {
    return null;
  }
  try {
    const expectedSig = crypto
      .createHmac("sha256", getAuthSecret())
      .update(`${headerB64}.${payloadB64}`)
      .digest();
    const providedSig = Buffer.from(sigB64, "base64url");
    if (expectedSig.length !== providedSig.length) {
      return null;
    }
    if (!crypto.timingSafeEqual(expectedSig, providedSig)) {
      return null;
    }
    const parsed = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8")
    ) as SessionJwtPayload;
    const now = Math.floor(Date.now() / 1000);
    if (!parsed.sub || !parsed.orgId || !parsed.exp || parsed.exp < now) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function slugifyWorkspace(input: string): string {
  const clean = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return clean || "workspace";
}

export function computeMerkleRoot(hashes: string[]): string {
  const GENESIS = "0000000000000000000000000000000000000000000000000000000000000000";
  if (hashes.length === 0) {
    return GENESIS;
  }
  let level = [...hashes];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1] ?? left;
      next.push(crypto.createHash("sha256").update(`${left}${right}`).digest("hex"));
    }
    level = next;
  }
  return level[0]!;
}

/**
 * Verifies an ECDSA P-256 signature encoded either in base64 DER (Rust gateway) or hex DER (Node service).
 */
export function verifyEcdsaP256(
  data: string,
  signature: string,
  publicKeyPem: string
): boolean {
  if (!signature || !publicKeyPem) {
    return false;
  }
  const formats: Array<"base64" | "hex"> = /^[0-9a-fA-F]+$/.test(signature)
    ? ["hex", "base64"]
    : ["base64", "hex"];

  for (const encoding of formats) {
    try {
      const verify = crypto.createVerify("SHA256");
      verify.update(data);
      verify.end();
      if (verify.verify(publicKeyPem, signature, encoding)) {
        return true;
      }
    } catch {
      // try fallback encoding
    }
  }
  return false;
}
