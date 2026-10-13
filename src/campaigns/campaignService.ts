// Creates campaigns, resolves the audience against synced data, and launches
// (enqueues a send job per recipient). Audience resolution is where synced
// groups become targeting.

import { store } from '../store';
import { sendQueue } from './queue';
import { makeToken } from '../tracking/tokens';
import type { Audience, Campaign, User } from '../types';

function resolveAudience(tenantId: string, audience: Audience): User[] {
  const enabled = store.usersForTenant(tenantId).filter(u => u.enabled);
  if (audience.kind === 'all') return enabled;
  const group = store.groupByName(tenantId, audience.groupName);
  if (!group) return [];
  const ids = new Set(group.memberExternalIds);
  return enabled.filter(u => ids.has(u.externalId));
}

export function createCampaign(input: {
  tenantId: string; name: string; templateId: string; audience: Audience;
}): Campaign {
  if (!store.getTemplate(input.templateId)) throw new Error(`unknown template ${input.templateId}`);
  return store.createCampaign({ ...input, status: 'draft' });
}

export function launchCampaign(campaignId: string): { recipients: number } {
  const campaign = store.getCampaign(campaignId);
  if (!campaign) throw new Error(`unknown campaign ${campaignId}`);

  const targets = resolveAudience(campaign.tenantId, campaign.audience);
  store.setCampaignStatus(campaignId, 'running');

  for (const user of targets) {
    // Create the recipient first (need its id), then sign a token for it.
    const recipient = store.createRecipient({
      campaignId, tenantId: campaign.tenantId, userId: user.id,
      email: user.email, status: 'queued', token: '',
    });
    recipient.token = makeToken(campaignId, recipient.id);
    sendQueue.enqueue({ recipientId: recipient.id });
  }
  return { recipients: targets.length };
}
