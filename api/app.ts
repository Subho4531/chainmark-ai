import { Hono } from "hono";
import { cors } from "hono/cors";
import { sql } from "drizzle-orm";
import { db } from "../db";
import { authRoutes } from "./routes/auth";
import { keysRoutes } from "./routes/keys";
import { ingestRoutes } from "./routes/ingest";
import { analyticsRoutes } from "./routes/analytics";
import type { AppVariables } from "./middleware";

export function createCloudApp() {
  const app = new Hono<{ Variables: AppVariables }>();

  app.use(
    "/api/*",
    cors({
      origin: (origin) => origin || "*",
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization", "X-Chainmark-Api-Key"],
      credentials: true,
    })
  );

  app.get("/api/cloud/health", async (c) => {
    try {
      await db.execute(sql`SELECT 1`);
      return c.json({
        ok: true,
        service: "Chainmark AI Cloud API",
        mode: process.env.DEPLOYMENT_MODE || "cloud",
        db: "connected",
      });
    } catch (err) {
      return c.json(
        {
          ok: false,
          service: "Chainmark AI Cloud API",
          mode: process.env.DEPLOYMENT_MODE || "cloud",
          db: "error",
          detail: err instanceof Error ? err.message : "unknown error",
        },
        503
      );
    }
  });

  app.route("/api/auth", authRoutes);
  app.route("/api/keys", keysRoutes);
  app.route("/api/ingest", ingestRoutes);
  app.route("/api/analytics", analyticsRoutes);

  return app;
}
