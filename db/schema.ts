import {
  pgTable,
  varchar,
  char,
  integer,
  bigint,
  text,
  timestamp,
  doublePrecision,
  jsonb,
  customType,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

// Custom PostgreSQL bytea type for raw binary AES-256-GCM ciphertexts and ZIP packages
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
  toDriver(val: Buffer): Buffer {
    return val;
  },
  fromDriver(val: unknown): Buffer {
    return Buffer.isBuffer(val) ? val : Buffer.from(val as string);
  },
});

// 0. Cloud Portal Multi-Tenant Tables (Option 2: Managed Cloud Auth & Billing)
export const users = pgTable("users", {
  id: varchar("id", { length: 64 }).primaryKey(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  name: varchar("name", { length: 120 }).notNull(),
  passwordHash: text("password_hash").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const organizations = pgTable("organizations", {
  id: varchar("id", { length: 64 }).primaryKey(),
  name: varchar("name", { length: 120 }).notNull(),
  slug: varchar("slug", { length: 80 }).notNull().unique(),
  plan: varchar("plan", { length: 32 }).default("cloud_usage").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const orgMembers = pgTable(
  "org_members",
  {
    id: bigint("id", { mode: "number" }).primaryKey().generatedAlwaysAsIdentity(),
    orgId: varchar("org_id", { length: 64 })
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: varchar("user_id", { length: 64 })
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    role: varchar("role", { length: 32 }).default("owner").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [uniqueIndex("unique_org_member").on(table.orgId, table.userId)]
);

export const apiKeys = pgTable(
  "api_keys",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    orgId: varchar("org_id", { length: 64 })
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    createdByUserId: varchar("created_by_user_id", { length: 64 }).references(() => users.id, {
      onDelete: "set null",
    }),
    name: varchar("name", { length: 120 }).notNull(),
    prefix: varchar("prefix", { length: 24 }).notNull(),
    keyHash: char("key_hash", { length: 64 }).notNull().unique(),
    scopes: jsonb("scopes").$type<string[]>().default(["intercept"]).notNull(),
    status: varchar("status", { length: 16 }).default("active").notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("idx_api_keys_org_status").on(table.orgId, table.status)]
);

// 1. Sessions Table (Option 2: holds org scope, state, Merkle root, ECDSA signature, and signer public key)
export const sessions = pgTable(
  "sessions",
  {
    sessionId: varchar("session_id", { length: 64 }).primaryKey(),
    orgId: varchar("org_id", { length: 64 }).references(() => organizations.id, {
      onDelete: "set null",
    }),
    status: varchar("status", { length: 32 }).default("ACTIVE").notNull(),
    merkleRoot: char("merkle_root", { length: 64 }).default("0000000000000000000000000000000000000000000000000000000000000000").notNull(),
    signature: text("signature"),
    signingPubkey: text("signing_pubkey"),
    totalEvents: integer("total_events").default(0).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    lastActive: timestamp("last_active", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("idx_sessions_org_active").on(table.orgId, table.lastActive)]
);

// 2. Vault Records (Encrypted tokens with AES-256-GCM)
export const vaultRecords = pgTable(
  "vault_records",
  {
    tokenId: varchar("token_id", { length: 64 }).primaryKey(),
    sessionId: varchar("session_id", { length: 64 })
      .notNull()
      .references(() => sessions.sessionId, { onDelete: "cascade" }),
    entityType: varchar("entity_type", { length: 32 }).notNull(),
    encryptedBlob: bytea("encrypted_blob").notNull(), // 12-byte IV + AES-GCM Ciphertext + 16-byte Tag
    valueDigest: char("value_digest", { length: 64 }).notNull(), // SHA-256 of plaintext
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("idx_vault_session_digest").on(table.sessionId, table.valueDigest),
  ]
);

// 3. Monotonic Merkle Evidence Event Log (Append-only)
export const merkleEvents = pgTable(
  "merkle_events",
  {
    id: bigint("id", { mode: "number" }).primaryKey().generatedAlwaysAsIdentity(),
    sessionId: varchar("session_id", { length: 64 })
      .notNull()
      .references(() => sessions.sessionId, { onDelete: "cascade" }),
    sequence: bigint("sequence", { mode: "number" }).notNull(),
    eventType: varchar("event_type", { length: 64 }).notNull(),
    inputDigest: char("input_digest", { length: 64 }).notNull(),
    sanitizedDigest: char("sanitized_digest", { length: 64 }).notNull(),
    policyAction: varchar("policy_action", { length: 64 }).notNull(),
    entitiesDetected: jsonb("entities_detected").$type<string[]>().default([]).notNull(),
    tokensMapped: jsonb("tokens_mapped").$type<string[]>().default([]).notNull(),
    eventTimestamp: doublePrecision("event_timestamp").default(0).notNull(),
    eventHash: char("event_hash", { length: 64 }).notNull(),
    prevHash: char("prev_hash", { length: 64 }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("unique_session_sequence").on(table.sessionId, table.sequence),
    index("idx_events_session_seq").on(table.sessionId, table.sequence),
  ]
);

// 4. Downloadable Evidence Packs (Option 2: Sealed portable ZIP receipts)
export const evidencePacks = pgTable("evidence_packs", {
  id: bigint("id", { mode: "number" }).primaryKey().generatedAlwaysAsIdentity(),
  sessionId: varchar("session_id", { length: 64 })
    .notNull()
    .references(() => sessions.sessionId, { onDelete: "cascade" }),
  merkleRoot: char("merkle_root", { length: 64 }).notNull(),
  signature: text("signature").notNull(),
  signingPubkey: text("signing_pubkey").notNull(),
  packZip: bytea("pack_zip").notNull(), // Binary .zip file containing chain.json, signature.sig, public_key.pem
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// Relations
export const organizationsRelations = relations(organizations, ({ many }) => ({
  members: many(orgMembers),
  apiKeys: many(apiKeys),
  sessions: many(sessions),
}));

export const usersRelations = relations(users, ({ many }) => ({
  memberships: many(orgMembers),
}));

export const orgMembersRelations = relations(orgMembers, ({ one }) => ({
  organization: one(organizations, {
    fields: [orgMembers.orgId],
    references: [organizations.id],
  }),
  user: one(users, {
    fields: [orgMembers.userId],
    references: [users.id],
  }),
}));

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  organization: one(organizations, {
    fields: [apiKeys.orgId],
    references: [organizations.id],
  }),
}));

export const sessionsRelations = relations(sessions, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [sessions.orgId],
    references: [organizations.id],
  }),
  vaultRecords: many(vaultRecords),
  merkleEvents: many(merkleEvents),
  evidencePacks: many(evidencePacks),
}));

export const vaultRecordsRelations = relations(vaultRecords, ({ one }) => ({
  session: one(sessions, {
    fields: [vaultRecords.sessionId],
    references: [sessions.sessionId],
  }),
}));

export const merkleEventsRelations = relations(merkleEvents, ({ one }) => ({
  session: one(sessions, {
    fields: [merkleEvents.sessionId],
    references: [sessions.sessionId],
  }),
}));

export const evidencePacksRelations = relations(evidencePacks, ({ one }) => ({
  session: one(sessions, {
    fields: [evidencePacks.sessionId],
    references: [sessions.sessionId],
  }),
}));

// Inferred TypeScript Types
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Organization = typeof organizations.$inferSelect;
export type NewOrganization = typeof organizations.$inferInsert;
export type OrgMember = typeof orgMembers.$inferSelect;
export type ApiKey = typeof apiKeys.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type VaultRecord = typeof vaultRecords.$inferSelect;
export type NewVaultRecord = typeof vaultRecords.$inferInsert;
export type MerkleEvent = typeof merkleEvents.$inferSelect;
export type NewMerkleEvent = typeof merkleEvents.$inferInsert;
export type EvidencePack = typeof evidencePacks.$inferSelect;
export type NewEvidencePack = typeof evidencePacks.$inferInsert;
