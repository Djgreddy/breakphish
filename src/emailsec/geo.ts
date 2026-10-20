// IP geolocation for the transport-chain map. Provider-agnostic and fail-open:
//   - maxmind: reads a local GeoLite2-City.mmdb (private; keeps customer IPs on
//     your server). Needs the free GeoLite2-City database downloaded to disk.
//   - ipapi: ip-api.com batch lookup (no key, but sends IPs to a third party).
//   - none (default): disabled — the UI shows the plain hop list.
//
// Results are cached per IP. Any error returns null (no coordinates), never throws.

import { config } from '../config';

export interface GeoPoint { lat: number; lon: number; city?: string; country?: string }
const cache = new Map<string, GeoPoint | null>();

function isPrivate(ip: string): boolean {
  return !ip || /^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1|fc|fd|fe80)/i.test(ip);
}

async function viaIpApi(ips: string[]): Promise<Record<string, GeoPoint | null>> {
  const res = await fetch('http://ip-api.com/batch?fields=status,lat,lon,city,country,query', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(ips.slice(0, 100).map(q => ({ query: q }))), signal: AbortSignal.timeout(3500),
  });
  if (!res.ok) throw new Error(`ip-api ${res.status}`);
  const arr = (await res.json()) as any[];
  const out: Record<string, GeoPoint | null> = {};
  for (const r of arr) out[r.query] = r.status === 'success' ? { lat: r.lat, lon: r.lon, city: r.city, country: r.country } : null;
  return out;
}

let mmReader: any = null;
async function maxmindReader() {
  if (mmReader) return mmReader;
  const mm: any = await import('maxmind');
  mmReader = await mm.open(config.geo.dbPath);
  return mmReader;
}
async function viaMaxmind(ip: string): Promise<GeoPoint | null> {
  const r: any = (await maxmindReader()).get(ip);
  if (!r?.location) return null;
  return { lat: r.location.latitude, lon: r.location.longitude, city: r.city?.names?.en, country: r.country?.names?.en };
}

export function geoEnabled(): boolean { return config.geo.provider !== 'none'; }

export async function geolocate(ips: string[]): Promise<Record<string, GeoPoint | null>> {
  const out: Record<string, GeoPoint | null> = {};
  const need: string[] = [];
  for (const ip of ips) {
    if (isPrivate(ip)) { out[ip] = null; continue; }
    if (cache.has(ip)) out[ip] = cache.get(ip)!; else need.push(ip);
  }
  if (!need.length || config.geo.provider === 'none') { for (const ip of need) out[ip] = null; return out; }
  try {
    if (config.geo.provider === 'ipapi') {
      const r = await viaIpApi(need);
      for (const ip of need) { cache.set(ip, r[ip] ?? null); out[ip] = r[ip] ?? null; }
    } else if (config.geo.provider === 'maxmind') {
      for (const ip of need) { const g = await viaMaxmind(ip).catch(() => null); cache.set(ip, g); out[ip] = g; }
    }
  } catch (e) {
    console.error('[geo]', (e as Error).message);
    for (const ip of need) out[ip] = null;
  }
  return out;
}
