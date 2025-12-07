// Database helper для тестов
import { pool } from "../../db/pool.js";
import fs from "fs/promises";
import path from "path";

/**
 * Очистка всех таблиц перед тестом
 * ВАЖНО: Проверяет что мы подключены к тестовой БД перед очисткой
 */
export async function clearDatabase(): Promise<void> {
  // Проверка что мы в тестовой БД (защита от удаления production данных)
  const result = await pool.query("SELECT current_database()");
  const dbName = result.rows[0].current_database;

  if (dbName !== "cryptox_test") {
    throw new Error(
      `❌ DANGER! Trying to clear production database '${dbName}'. Tests should only use 'cryptox_test'`,
    );
  }
  // Список всех таблиц для очистки (в правильном порядке из-за FK)
  const tables = [
    "reactions",
    "pinned_messages",
    "group_messages",
    "group_invites",
    "group_members",
    "groups",
    "pending_messages",
    "media_files",
    "messages",
    "contacts",
    "calls",
    "push_subscriptions",
    "audit_log",
    "pending_sessions",
    "primary_devices",
    "password_recovery",
    "email_verifications",
    "sessions",
    "users",
  ];

  // Очищаем ВСЕ таблицы ОДНИМ запросом - это предотвращает deadlock
  // при параллельном запуске тестов, т.к. используется одна блокировка
  try {
    // Формируем список таблиц через запятую
    const tableList = tables.join(", ");
    await pool.query(`TRUNCATE TABLE ${tableList} RESTART IDENTITY CASCADE`);
  } catch (err: any) {
    // Если какая-то таблица не существует - очищаем по одной
    for (const table of tables) {
      try {
        await pool.query(`TRUNCATE TABLE ${table} RESTART IDENTITY CASCADE`);
      } catch (tableErr: any) {
        // Игнорируем ошибку "таблица не существует"
        if (!tableErr.message.includes("does not exist")) {
          console.warn(
            `Warning: Failed to truncate ${table}:`,
            tableErr.message,
          );
        }
      }
    }
  }
}

/**
 * Запуск миграций (создание таблиц)
 */
export async function runMigrations(): Promise<void> {
  const client = await pool.connect();

  try {
    const migrationsDir = path.join(process.cwd(), "src", "db", "migrations");
    const files = await fs.readdir(migrationsDir);

    // Сортируем файлы по номеру (001, 002, ...)
    const sqlFiles = files.filter((f) => f.endsWith(".sql")).sort();

    for (const file of sqlFiles) {
      const filePath = path.join(migrationsDir, file);
      const sql = await fs.readFile(filePath, "utf-8");
      await client.query(sql);
      console.log(`✅ Migration ${file} completed`);
    }

    console.log("✅ All test database migrations completed");
  } catch (err) {
    console.error("❌ Migration failed:", err);
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Закрытие pool connection после всех тестов
 *
 * NOTE: We don't actually close the pool here because tests run in parallel.
 * If one test file closes the pool, all other running tests will fail with
 * "Cannot use a pool after calling end on the pool".
 * The pool will be closed automatically when the process exits.
 */
export async function closeDatabase(): Promise<void> {
  // Do nothing - let process exit handle pool cleanup
  // This prevents "Cannot use a pool after calling end on the pool" errors
  // when tests run in parallel
}

/**
 * Получение количества записей в таблице
 */
export async function getTableCount(tableName: string): Promise<number> {
  const result = await pool.query(`SELECT COUNT(*) FROM ${tableName}`);
  return parseInt(result.rows[0].count, 10);
}

/**
 * Проверка существования пользователя
 */
export async function userExists(username: string): Promise<boolean> {
  const result = await pool.query(
    "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
    [username],
  );
  return result.rows[0].exists;
}

/**
 * Получение пользователя по username
 */
export async function getUser(username: string): Promise<any> {
  const result = await pool.query("SELECT * FROM users WHERE username = $1", [
    username,
  ]);
  return result.rows[0] || null;
}

/**
 * Проверка существования сессии
 */
export async function sessionExists(sessionId: string): Promise<boolean> {
  const result = await pool.query(
    "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1)",
    [sessionId],
  );
  return result.rows[0].exists;
}

/**
 * Получение всех устройств пользователя
 */
export async function getUserDevices(username: string): Promise<any[]> {
  const result = await pool.query(
    "SELECT * FROM primary_devices WHERE username = $1 ORDER BY created_at DESC",
    [username],
  );
  return result.rows;
}
