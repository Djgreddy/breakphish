// Tracks AI classifier usage so the partner can see real volume/cost: how many
// LLM calls, tokens in/out, how many messages were scored (→ ambiguous rate),
// aggregated per month. Write-through to Postgres, debounced.

import { dbEnabled, q } from './db/db';

interface MonthRow { month: string; calls: number; inputTokens: number; outputTokens: number; scored: number }
const months = new Map<string, MonthRow>();
const dirty = new Set<string>();

function thisMonth(): string { return new Date().toISOString().slice(0, 7); }
function row(month: string): MonthRow {
  let r = months.get(month);
  if (!r) { r = { month, calls: 0, inputTokens: 0, outputTokens: 0, scored: 0 }; months.set(month, r); }
  return r;
}

export function recordLlmCall(inputTokens: number, outputTokens: number): void {
  const r = row(thisMonth()); r.calls++; r.inputTokens += inputTokens || 0; r.outputTokens += outputTokens || 0;
  dirty.add(r.month); scheduleFlush();
}
export function recordScored(): void {
  const r = row(thisMonth()); r.scored++; dirty.add(r.month); scheduleFlush();
}

export function getUsage() {
  const list = [...months.values()].sort((a, b) => a.month < b.month ? 1 : -1);
  const cur = row(thisMonth());
  const lifetime = list.reduce((acc, r) => ({ calls: acc.calls + r.calls, inputTokens: acc.inputTokens + r.inputTokens, outputTokens: acc.outputTokens + r.outputTokens, scored: acc.scored + r.scored }), { calls: 0, inputTokens: 0, outputTokens: 0, scored: 0 });
  return {
    current: cur,
    ambiguousRate: cur.scored ? Math.round((cur.calls / cur.scored) * 100) : 0,
    months: list.slice(0, 6),
    lifetime,
  };
}

let flushTimer: any = null;
function scheduleFlush() {
  if (!dbEnabled() || flushTimer) return;
  flushTimer = setTimeout(() => { flushTimer = null; flush().catch(() => {}); }, 5000);
}
async function flush() {
  for (const m of [...dirty]) {
    const r = months.get(m); if (!r) continue;
    await q(
      `insert into ai_usage (month, calls, input_tokens, output_tokens, scored)
       values ($1,$2,$3,$4,$5)
       on conflict (month) do update set calls=excluded.calls, input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens, scored=excluded.scored`,
      [r.month, r.calls, r.inputTokens, r.outputTokens, r.scored],
    );
    dirty.delete(m);
  }
}

export async function hydrateAiUsage(): Promise<void> {
  if (!dbEnabled()) return;
  const rows = await q<any>('select * from ai_usage');
  for (const r of rows) months.set(r.month, { month: r.month, calls: Number(r.calls), inputTokens: Number(r.input_tokens), outputTokens: Number(r.output_tokens), scored: Number(r.scored) });
}
