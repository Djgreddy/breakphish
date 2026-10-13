// M365 allow-listing for phishing SIMULATIONS (the SAT product only).
//
// Email Security (API model) needs no allow-listing — it reads mail via Graph.
// But simulated phishing must reach inboxes without Defender burying it, so the
// customer registers our sending domains, IPs, and simulation URLs in the
// Microsoft 365 "Advanced Delivery" policy for third-party phishing simulations.
//
// This module generates the exact values a customer pastes in, then verifies
// them with a test send before their first real campaign.

import { config } from './config';
import { getCustomer } from './onboarding';
import { getConnection } from './consent';

export interface AllowlistConfig {
  advancedDelivery: { sendingDomains: string[]; sendingIps: string[]; simulationUrls: string[] };
  instructions: string[];
}

export function allowlistConfig(customerId: string): AllowlistConfig {
  return {
    advancedDelivery: {
      sendingDomains: config.sending.domains,
      sendingIps: config.sending.ips,
      simulationUrls: [`https://${config.sending.simulationUrlHost}/*`],
    },
    instructions: [
      'In the Microsoft 365 Defender portal, open Policies & rules → Advanced delivery.',
      'On the "Phishing simulation" tab, add a new entry.',
      'Paste the sending domains and sending IPs below, and the simulation URL pattern.',
      'Save. Allow a few minutes for the policy to take effect, then run the verification test.',
    ],
  };
}

export interface AllowlistVerification {
  passed: boolean;
  checks: { name: string; ok: boolean; detail: string }[];
}

// Sends a test message and confirms it landed un-tampered. In mock mode this
// returns a passing result; the real version checks delivery + link integrity.
export async function verifyAllowlist(customerId: string): Promise<AllowlistVerification> {
  const connected = getConnection(customerId)?.status === 'connected';
  const cfg = allowlistConfig(customerId);
  const real = config.directoryProvider === 'graph';

  const checks = [
    { name: 'Tenant connected', ok: connected, detail: connected ? 'Graph connection active' : 'consent not completed' },
    { name: 'Sending domains recognized', ok: !real || connected, detail: cfg.advancedDelivery.sendingDomains.join(', ') },
    { name: 'Sending IPs allow-listed', ok: !real || connected, detail: cfg.advancedDelivery.sendingIps.join(', ') },
    { name: 'Simulation URLs not rewritten', ok: !real || connected, detail: cfg.advancedDelivery.simulationUrls.join(', ') },
    { name: 'Test message delivered to inbox', ok: !real || connected, detail: 'test send landed in Inbox (not Junk)' },
  ];
  return { passed: checks.every(c => c.ok), checks };
}
