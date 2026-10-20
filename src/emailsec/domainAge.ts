// Newly-registered domains are disproportionately malicious. We look up a domain's
// registration date via RDAP (free, no key) and cache the result. Fail-open: any
// error/timeout returns null (no signal), so detection is never blocked by it.

const cache = new Map<string, { days: number | null; at: number }>();
const TTL = 7 * 864e5; // re-check weekly

export async function domainAgeDays(domain: string): Promise<number | null> {
  domain = (domain || '').toLowerCase().replace(/^www\./, '');
  if (!domain || !domain.includes('.')) return null;
  const cached = cache.get(domain);
  if (cached && Date.now() - cached.at < TTL) return cached.days;

  let days: number | null = null;
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(2500) });
    if (res.ok) {
      const j: any = await res.json();
      const reg = (j.events ?? []).find((e: any) => e.eventAction === 'registration');
      if (reg?.eventDate) {
        const d = Date.parse(reg.eventDate);
        if (!Number.isNaN(d)) days = Math.max(0, Math.floor((Date.now() - d) / 864e5));
      }
    }
  } catch { /* network/timeout/unsupported TLD — fail open */ }
  cache.set(domain, { days, at: Date.now() });
  return days;
}
