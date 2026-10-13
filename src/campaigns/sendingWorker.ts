// Consumes the send queue. For each recipient: build tracking URLs, render the
// template, send via transport, mark the recipient sent, record a 'delivered'
// event.

import { store } from '../store';
import { config } from '../config';
import { sendQueue, type SendJob } from './queue';
import { makeTransport } from './transport';
import { render } from './templates';

const transport = makeTransport();

export function startSendingWorker() {
  sendQueue.onJob(async (job: SendJob) => {
    const r = store.getRecipient(job.recipientId);
    if (!r) return;
    const campaign = store.getCampaign(r.campaignId)!;
    const template = store.getTemplate(campaign.templateId)!;
    const user = store.usersForTenant(r.tenantId).find(u => u.id === r.userId)!;
    const tenant = store.getTenant(r.tenantId)!;

    const clickUrl = `${config.publicBaseUrl}/t/c/${r.token}`;
    const openUrl = `${config.publicBaseUrl}/t/o/${r.token}`;
    const email = render(template, user, tenant.name, clickUrl, openUrl);

    const { delivered } = await transport.send(email);
    store.setRecipientStatus(r.id, delivered ? 'sent' : 'bounced');
    store.recordEvent({
      campaignId: r.campaignId, recipientId: r.id, tenantId: r.tenantId,
      type: delivered ? 'delivered' : 'bounced',
    });
  });
}
