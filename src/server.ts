// Standalone tracking server (the component that would run as a service).
// Run: npm run server

import { createServer } from 'node:http';
import { config } from './config';
import { seedTemplates } from './campaigns/templates';
import { startSendingWorker } from './campaigns/sendingWorker';
import { buildTrackingApp } from './tracking/trackingServer';

seedTemplates();
startSendingWorker();

createServer(buildTrackingApp()).listen(config.port, () => {
  console.log(`BreakPhish tracking server listening on ${config.publicBaseUrl}`);
});
