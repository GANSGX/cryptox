import pg from 'pg';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/cryptox',
});

async function applyMigration() {
  const client = await pool.connect();

  try {
    console.log('🚀 Applying migration 013...\n');

    const sql = readFileSync(join(__dirname, '..', 'apply_migration_013.sql'), 'utf-8');

    await client.query(sql);

    console.log('✅ Migration 013 applied successfully!\n');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

applyMigration();
