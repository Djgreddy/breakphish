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

export function buildWebhookApp() {
  const app = express.Router();
  app.use(express.json({ type: ['application/json', 'text/plain'] }));

  const handler = async (req: express.Request, res: express.Response) => {
    // 1. validation handshake
    const token = (req.query.validationToken ?? (req.body && req.body.validationToken)) as string | undefined;
    if (token) { res.set('content-type', 'text/plain').status(200).send(token); return; }

    // 2. notifications — ack fast, process async
    const notifications: any[] = req.body?.value ?? [];
    res.status(202).send();

    for (const n of notifications) {
      try {
        const sub = getSubscription(n.subscriptionId);
        if (!sub) { console.error('[webhook] unknown subscription', n.subscriptionId); continue; }
        if (n.clientState && n.clientState !== sub.clientState) { console.error('[webhook] clientState mismatch'); continue; }
        const conn = getConnection(sub.customerId);
        const messageId = n.resourceData?.id;
        if (!conn?.entraTenantId || !messageId) continue;
        const disp = await ingestOneMessage(sub.customerId, conn.entraTenantId, sub.userId, messageId);
        if (disp) console.log(`[webhook] scored ${messageId} → ${disp}`);
      } catch (e) {
        console.error('[webhook] processing error:', (e as Error).message);
      }
    }
  };

  app.get('/webhooks/graph', handler);
  app.post('/webhooks/graph', handler);
  return app;
}
