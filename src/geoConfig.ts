// Partner-wide geolocation configuration (for the transport-chain map). Same
// pattern as the AI provider: environment variables win and lock the UI; otherwise
// the DB-stored config (set through the WebUI) is used. No secrets here (MaxMind
// uses a local file; ip-api needs no key), so nothing is encrypted.

import { config } from './config';
import { dbEnabled, q } from './db/db';

export type GeoProvider = 'none' | 'maxmind' | 'ipapi';
let db: { provider: GeoProvider; dbPath: string } = { provider: 'none', dbPath: '/opt/breakphish/GeoLite2-City.mmdb' };

const envConfigured = () => (process.env.GEOIP_PROVIDER ?? 'none') !== 'none';

export function getGeoConfig(): { provider: GeoProvider; dbPath: string; source: 'env' | 'db' | 'none' } {
  if (envConfigured()) return { provider: config.geo.provider, dbPath: config.geo.dbPath, source: 'env' };
  if (db.provider !== 'none') return { provider: db.provider, dbPath: db.dbPath, source: 'db' };
  return { provider: 'none', dbPath: db.dbPath, source: 'none' };
}

export function publicGeoConfig() {
  const eff = getGeoConfig();
  const locked = envConfigured();
  const shown = locked ? config.geo : db;
  return { provider: shown.provider, dbPath: shown.dbPath || '', locked, source: eff.source, active: eff.provider !== 'none' };
}

// Called when config changes so the geo module reopens any cached DB reader.
let onChange: (() => void) | null = null;
export function onGeoConfigChange(fn: () => void) { onChange = fn; }

export async function saveGeoConfig(input: { provider: GeoProvider; dbPath?: string }): Promise<void> {
  if (envConfigured()) throw new Error('Geolocation is managed via environment variables and cannot be changed here.');
  db.provider = input.provider;
  if (input.dbPath) db.dbPath = input.dbPath;
  if (dbEnabled()) {
    await q(`insert into geo_config (id, provider, db_path, updated_at) values ('partner', $1, $2, now())
             on conflict (id) do update set provider=excluded.provider, db_path=excluded.db_path, updated_at=now()`,
      [db.provider, db.dbPath]);
  }
  onChange?.();
}

export async function hydrateGeoConfig(): Promise<void> {
  if (!dbEnabled()) return;
  const rows = await q<any>(`select * from geo_config where id='partner'`);
  const r = rows[0]; if (!r) return;
  db = { provider: r.provider ?? 'none', dbPath: r.db_path ?? db.dbPath };
}
