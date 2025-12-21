import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { pool } from "./pool.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function runMigrations() {
  const client = await pool.connect();

  try {
    console.log("🚀 Starting migrations...\n");

    // Создаём таблицу для отслеживания миграций
    await client.query(`
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        executed_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Список миграций
    const migrations = [
      "001_initial_schema.sql",
      "002_messages_and_media.sql",
      "003_groups.sql",
      "004_reactions_calls_audit.sql",
      "005_add_primary_device.sql",
      "006_add_device_fingerprint.sql",
      "007_add_primary_devices_table.sql",
      "008_add_pending_sessions.sql",
      "009_add_signal_protocol_keys.sql",
      "010_add_delivered_at.sql",
      "011_add_message_edit_delete.sql",
      "012_add_profile_fields.sql",
      "013_add_profile_photos.sql",
    ];

    for (const migration of migrations) {
      // Проверяем выполнялась ли миграция
      const { rows } = await client.query(
        "SELECT * FROM migrations WHERE name = $1",
        [migration],
      );

      if (rows.length > 0) {
        console.log(`⏭️  Skipping ${migration} (already applied)`);
        continue;
      }

      // Читаем SQL файл
      const sql = readFileSync(
        join(__dirname, "migrations", migration),
        "utf-8",
      );

      // Выполняем миграцию
      console.log(`▶️  Applying ${migration}...`);
      await client.query(sql);

      // Записываем в таблицу миграций
      await client.query("INSERT INTO migrations (name) VALUES ($1)", [
        migration,
      ]);

      console.log(`✅ Applied ${migration}\n`);
    }

    console.log("🎉 All migrations completed!");
  } catch (error) {
    console.error("❌ Migration failed:", error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

runMigrations();
