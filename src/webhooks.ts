// Public endpoint that receives Microsoft Graph change notifications.
//
// Two jobs:
//   1. Validation handshake — on subscription creation Graph sends a GET/POST
//      with ?validationToken=...; we must echo it as text/plain within 10s.
//   2. Notifications — Graph POSTs { value: [ { subscriptionId, clientState,
//      resourceData: { id } } ] } when new mail arrives. We validate the
//      clientState (shared secret), map the subscription to a customer+mailbox,
//      then fetch+score+act on that one message — in the background, replying 202
//      immediately so Graph doesn't time out.
//
// This router is mounted WITHOUT auth (Microsoft can't send a session), but every
// notification is authenticated by its clientState matching our stored value.

import express from 'express';
import { getSubscription } from './emailsec/subscriptions';
import { getConnection } from './consent';
import { ingestOneMessage } from './emailsec/mailIngest';

// Global bounded work queue: at most MAX_CONCURRENT message ingests run at once,
// no matter how many webhook notifications flood in. Extra work waits in line,
// so a burst can't spawn hundreds of concurrent Graph calls and exhaust memory.
const MAX_CONCURRENT = 4;
const workQueue: Array<() => Promise<void>> = [];
let activeWorkers = 0;
function drainQueue() {
  while (activeWorkers < MAX_CONCURRENT && workQueue.length) {
    const task = workQueue.shift()!;
    activeWorkers++;
    task().finally(() => { activeWorkers--; drainQueue(); });
  }
}
export function enqueueWork(task: () => Promise<void>) {
  if (workQueue.length > 5000) { console.error('[webhook] queue overloaded, dropping notification'); return; }
  workQueue.push(task);
  drainQueue();
}
import { markWebhook } from './connHealth';

export function buildWebhookApp() {
  const app = express.Router();

  // Respond to the validation handshake FIRST — before any body parsing — so a
  // slow/odd body can never make us miss Graph's ~10s window.
  const echoValidation = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const t = req.query.validationToken as string | undefined;
    if (t) { res.set('content-type', 'text/plain').status(200).send(String(t)); return; }
    next();
  };

  const handler = async (req: express.Request, res: express.Response) => {
    // notifications — ack fast, process through a bounded queue (prevents a burst of
    // notifications from spawning hundreds of concurrent Graph calls → OOM).
    const notifications: any[] = req.body?.value ?? [];
    res.status(202).send();

    for (const n of notifications) {
      const sub = getSubscription(n.subscriptionId);
      if (!sub) { console.error('[webhook] unknown subscription', n.subscriptionId); continue; }
      if (n.clientState && n.clientState !== sub.clientState) { console.error('[webhook] clientState mismatch'); continue; }
      const conn = getConnection(sub.customerId);
      const messageId = n.resourceData?.id;
      if (!conn?.entraTenantId || !messageId) continue;
      markWebhook(sub.customerId);
      enqueueWork(async () => {
        try {
          const disp = await ingestOneMessage(sub.customerId, conn.entraTenantId!, sub.userId, messageId);
          if (disp) console.log(`[webhook] scored ${messageId} → ${disp}`);
        } catch (e) { console.error('[webhook] processing error:', (e as Error).message); }
      });
    }
  };

  const jsonBody = express.json({ type: () => true, limit: '1mb' });
  app.get('/webhooks/graph', echoValidation, handler);
  app.post('/webhooks/graph', echoValidation, jsonBody, handler);

  // Link-rewrite protection redirect. Rewritten links in mail point here; we log
  // the click and forward to the real URL (an interstitial could warn for risky ones).
  app.get('/l', (req, res) => {
    const target = String(req.query.u ?? '');
    let url: URL;
    try { url = new URL(target); } catch { return res.status(400).send('Invalid link'); }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return res.status(400).send('Blocked link');
    console.log(`[linkrw] click → ${url.hostname}`);
    res.redirect(302, url.toString());
  });

  return app;
}
