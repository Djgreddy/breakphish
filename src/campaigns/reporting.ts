import { store } from '../store';

export function campaignFunnel(campaignId: string) {
  const recipients = store.recipientsForCampaign(campaignId);
  const events = store.eventsForCampaign(campaignId);
  const count = (t: string) => new Set(events.filter(e => e.type === t).map(e => e.recipientId)).size;

  const sent = recipients.filter(r => r.status === 'sent').length;
  const clicked = count('clicked');
  return {
    recipients: recipients.length,
    delivered: count('delivered') || sent,
    opened: count('opened'),
    clicked,
    submitted: count('submitted'),
    reported: count('reported'),
    phishPronePct: recipients.length ? Math.round((clicked / recipients.length) * 1000) / 10 : 0,
  };
}
