import "dotenv/config";
import { sql } from "drizzle-orm";
import { db, client } from "../db/index";

async function main() {
  console.log("Connecting to PostgreSQL at 127.0.0.1:5432/docklet...");
  const result = await db.execute(
    sql`SELECT NOW() as current_time, current_database() as database, current_user as user, version() as version`
  );
  console.log("Drizzle ORM Ping Result:");
  console.log(result);
  await client.end();
}

main().catch((err) => {
  console.error("Drizzle Ping Error:", err);
  process.exit(1);
});
