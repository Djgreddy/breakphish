// The loop that makes simulations worthwhile: a click or submit auto-enrolls the
// user in a remediation module within seconds, while the teachable moment is
// fresh. Repeat offenders could be escalated to a longer path here too.

import { store } from '../store';
import { config } from '../config';
import type { Recipient } from '../types';

export function remediateOnClick(recipient: Recipient, reason: string) {
  const campaign = store.getCampaign(recipient.campaignId);
  const enrolled = store.enroll({
    tenantId: recipient.tenantId,
    userId: recipient.userId,
    moduleId: config.remediationModuleId,
    reason: `${reason}:${campaign?.name ?? recipient.campaignId}`,
  });
  if (enrolled) {
    const user = store.usersForTenant(recipient.tenantId).find(u => u.id === recipient.userId);
    console.log(
      `   🎓 [remediation] enrolled ${user?.email} in "${config.remediationModuleId}" (reason: ${reason})`,
    );
  }
}
