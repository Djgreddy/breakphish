// The internet-facing tracking surface. Every endpoint verifies the HMAC token,
// records exactly one event, and (for click/submit) triggers remediation.
//
// SECURITY INVARIANT: the submit endpoint NEVER reads, logs, or stores the
// posted body. It records only that a submission happened. This is enforced
// below by simply not touching req body contents.

import express from 'express';
import { store } from '../store';
import { verifyToken } from './tokens';
import { remediateOnClick } from '../training/remediation';
import type { EventType } from '../types';

// 1x1 transparent GIF.
const PIXEL = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

function teachablePage(): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Simulated phishing test</title>
  <style>body{font-family:system-ui;background:#0c111b;color:#e8edf5;display:grid;place-items:center;height:100vh;margin:0}
  .c{max-width:440px;text-align:center;padding:32px}.b{width:60px;height:60px;border-radius:16px;background:#f3b34022;display:grid;place-items:center;margin:0 auto 18px;font-size:28px}
  h1{font-size:22px;margin:0 0 10px}p{color:#8a97ac;line-height:1.6}</style></head>
  <body><div class="c"><div class="b">⚠️</div><h1>This was a simulated phishing test</h1>
  <p>No harm done — this came from your security team. Real attackers use messages exactly like this to steal credentials.
  You've been assigned a short training module to help you spot the next one.</p>
  <p>Red flags here: urgent deadline, mismatched sender domain, and a link that didn't go where it claimed.</p></div></body></html>`;
}

function resolveRecipient(token: string) {
  const v = verifyToken(token);
  if (!v) return null;
  const r = store.getRecipient(v.recipientId);
  if (!r || r.campaignId !== v.campaignId) return null;
  return r;
}

function record(token: string, type: EventType) {
  const r = resolveRecipient(token);
  if (!r) return null;
  store.recordEvent({ campaignId: r.campaignId, recipientId: r.id, tenantId: r.tenantId, type });
  return r;
}

export function buildTrackingApp() {
  const app = express();
  // We accept a body on submit but deliberately never inspect it.
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());

  // Open pixel.
  app.get('/t/o/:token', (req, res) => {
    record(req.params.token, 'opened');
    res.set('content-type', 'image/gif').set('cache-control', 'no-store').send(PIXEL);
  });

  // Click → record, remediate, show teachable moment.
  app.get('/t/c/:token', (req, res) => {
    const r = record(req.params.token, 'clicked');
    if (r) remediateOnClick(r, 'clicked');
    res.set('content-type', 'text/html').send(teachablePage());
  });

  // Submit → record only. The posted credentials are never touched.
  app.post('/t/s/:token', (req, res) => {
    const r = record(req.params.token, 'submitted');
    if (r) remediateOnClick(r, 'submitted');
    // Note: req.body exists but is intentionally ignored and not persisted.
    res.set('content-type', 'text/html').send(teachablePage());
  });

  // Report → positive signal (reported a phish). No remediation needed.
  app.post('/t/r/:token', (req, res) => {
    record(req.params.token, 'reported');
    res.json({ ok: true, message: 'Thanks for reporting.' });
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  return app;
}
