// Postgres access layer. One pooled connection, a tiny query helper, and a
// bootstrap that applies db/schema.sql on startup (idempotent — every statement
// is CREATE ... IF NOT EXISTS). Reads DATABASE_URL; when it's unset the app runs
// in in-memory mode and this module stays dormant.

import { Pool } from 'pg';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

let pool: Pool | null = null;

export function dbEnabled(): boolean {
  return Boolean(process.env.DATABASE_URL);
}

export function getPool(): Pool {
  if (!pool) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not set');
    // The pg library now treats `sslmode=require` as full verification, which
    // rejects DigitalOcean's CA ("self-signed certificate in certificate chain").
    // Strip sslmode from the URL and control TLS here instead.
    const connectionString = process.env.DATABASE_URL
      .replace(/([?&])sslmode=[^&]*/i, '$1')
      .replace(/[?&]+$/, '');

    // Default: encrypt but don't verify the chain (fine for a private-VPC pilot).
    // To pin properly (recommended before production): set DATABASE_CA_FILE to
    // DigitalOcean's CA cert and this verifies against it.
    let ssl: any = { rejectUnauthorized: false };
    if (process.env.DATABASE_CA_FILE) {
      ssl = { ca: readFileSync(process.env.DATABASE_CA_FILE, 'utf8'), rejectUnauthorized: true };
    }

    pool = new Pool({
      connectionString,
      ssl,
      max: Number(process.env.DB_POOL_MAX ?? 10),
      idleTimeoutMillis: 30000,
    });
    pool.on('error', (e) => console.error('[db] pool error', e));
  }
  return pool;
}

// Run a query. Returns rows typed as T.
export async function q<T = any>(text: string, params: any[] = []): Promise<T[]> {
  const res = await getPool().query(text, params);
  return res.rows as T[];
}

// Convenience: first row or null.
export async function one<T = any>(text: string, params: any[] = []): Promise<T | null> {
  const rows = await q<T>(text, params);
  return rows[0] ?? null;
}

// Apply the schema. Safe to run on every boot.
export async function migrate(): Promise<void> {
  const schema = readFileSync(join(__dirname, '..', '..', 'db', 'schema.sql'), 'utf8');
  await getPool().query(schema);
  console.log('[db] schema applied');
}

// Verify connectivity (used by health / startup).
export async function ping(): Promise<boolean> {
  try { await getPool().query('select 1'); return true; }
  catch { return false; }
}

export async function closePool(): Promise<void> {
  if (pool) { await pool.end(); pool = null; }
}
