import "dotenv/config";
import { client, db } from "../db/index";
import { storeTokenizedItem, retrieveTokenizedItem, detokenizeText } from "../db/vault";
import { EvidenceService } from "../db/evidence";
import { sessions, vaultRecords, merkleEvents, evidencePacks } from "../db/schema";
import { eq } from "drizzle-orm";

async function runOption2Verification() {
  console.log("==================================================================");
  console.log("   CHAINMARK AI: OPTION 2 VERIFICATION TEST (DRIZZLE + POSTGRES)   ");
  console.log("==================================================================");

  const sessionId = `test_session_${Date.now()}`;
  const evidenceService = new EvidenceService();

  // 1. Create Session in PostgreSQL
  console.log(`\n[+] Step 1: Initializing session '${sessionId}' in PostgreSQL...`);
  const session = await evidenceService.getOrCreateSession(sessionId);
  console.log(`    Session created: status='${session.status}'`);

  // 2. Tokenize & Vault Sensitive PII (AES-256-GCM)
  console.log(`\n[+] Step 2: Vaulting sensitive PII with AES-256-GCM...`);
  const aadhaar = "999999990019";
  const creditCard = "4532015112830366";

  const { tokenId: aadhaarToken } = await storeTokenizedItem({
    sessionId,
    entityType: "AADHAAR",
    rawValue: aadhaar,
  });
  console.log(`    Aadhaar masked as token: ${aadhaarToken}`);

  const { tokenId: cardToken } = await storeTokenizedItem({
    sessionId,
    entityType: "CREDIT_CARD",
    rawValue: creditCard,
  });
  console.log(`    Card masked as token:    ${cardToken}`);

  // Verify records in PostgreSQL are encrypted bytes (zero plaintext)
  const [dbRecord] = await db
    .select()
    .from(vaultRecords)
    .where(eq(vaultRecords.tokenId, aadhaarToken));

  if (!dbRecord.encryptedBlob || dbRecord.encryptedBlob.includes(Buffer.from(aadhaar))) {
    throw new Error("Zero Plaintext Leakage VIOLATION: raw plaintext found in encrypted_blob!");
  }
  console.log(`    Verified DB storage: encrypted_blob length is ${dbRecord.encryptedBlob.length} bytes (AES-256-GCM)`);

  // 3. Detokenization Roundtrip Test
  console.log(`\n[+] Step 3: Detokenizing tokens back to original plaintext...`);
  const restoredAadhaar = await retrieveTokenizedItem({ sessionId, tokenId: aadhaarToken });
  if (restoredAadhaar !== aadhaar) {
    throw new Error(`Detokenization failed: expected ${aadhaar}, got ${restoredAadhaar}`);
  }
  console.log(`    Successfully restored Aadhaar: ${restoredAadhaar}`);

  const maskedText = `User has Aadhaar ${aadhaarToken} and payment card ${cardToken}.`;
  const { text: uncloakedText, unresolvedCount } = await detokenizeText(maskedText, sessionId);
  console.log(`    Full text uncloak result: "${uncloakedText}" (unresolved: ${unresolvedCount})`);

  // 4. Record Sequential Merkle Events in PostgreSQL
  console.log(`\n[+] Step 4: Recording append-only Merkle events in PostgreSQL...`);
  const event1 = await evidenceService.appendEvent({
    sessionId,
    eventType: "LLM_PROMPT_EGRESS",
    rawInput: `My Aadhaar is ${aadhaar}`,
    sanitizedOutput: `My Aadhaar is ${aadhaarToken}`,
    policyAction: "TOKENIZE_AND_FORWARD",
  });
  console.log(`    Event 0 recorded: seq=${event1.sequence}, eventHash=${event1.eventHash.slice(0, 16)}...`);

  const event2 = await evidenceService.appendEvent({
    sessionId,
    eventType: "LLM_COMPLETION_INGRESS",
    rawInput: `Verification code sent to Aadhaar ${aadhaarToken}`,
    sanitizedOutput: `Verification code sent to Aadhaar ${aadhaar}`,
    policyAction: "DETOKENIZE_FOR_CLIENT",
  });
  console.log(`    Event 1 recorded: seq=${event2.sequence}, eventHash=${event2.eventHash.slice(0, 16)}...`);

  // 5. Close Session & Generate Signed Merkle Evidence Receipt ZIP
  console.log(`\n[+] Step 5: Sealing session & generating ECDSA P-256 signed receipt...`);
  const { merkleRoot, signature, zipBytes } = await evidenceService.closeSessionAndSealReceipt(sessionId);
  console.log(`    Merkle Root: ${merkleRoot}`);
  console.log(`    ECDSA Sig:   ${signature.slice(0, 32)}...`);
  console.log(`    Receipt ZIP: ${zipBytes.length} bytes (persisted in evidence_packs table)`);

  // 6. Verify Sealed Receipt Package Offline
  console.log(`\n[+] Step 6: Verifying portable receipt ZIP offline...`);
  const verification = await evidenceService.verifyReceiptPack(zipBytes);
  if (!verification.verified) {
    throw new Error(`Receipt verification FAILED: ${verification.error}`);
  }
  console.log(`    Receipt Verification SUCCESSFUL!`);
  console.log(`    Verified events count: ${verification.totalEvents}`);
  console.log(`    Cryptographic integrity: 100% VALID`);

  console.log("\n==================================================================");
  console.log("   ALL OPTION 2 DRIZZLE + POSTGRESQL VERIFICATION TESTS PASSED!   ");
  console.log("==================================================================");

  await client.end();
}

runOption2Verification().catch(async (e) => {
  console.error("\n❌ Test execution failed:", e);
  await client.end();
  process.exit(1);
});
