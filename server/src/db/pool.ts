import pg from "pg";
import { env } from "../config/env.js";

const { Pool } = pg;

// Автоматическое переключение между production и test БД
const databaseUrl =
  env.NODE_ENV === "test" ? env.TEST_DATABASE_URL : env.DATABASE_URL;

export const pool = new Pool({
  connectionString: databaseUrl,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Тест подключения
pool.on("connect", () => {
  console.log("✅ Connected to PostgreSQL");
});

pool.on("error", (err) => {
  console.error("❌ PostgreSQL error:", err);
  process.exit(-1);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  await pool.end();
  console.log("🔌 PostgreSQL pool closed");
  process.exit(0);
});
