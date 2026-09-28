import { buildApp } from './app';
import { createCasClient } from './cas-client';
import { loadEnv } from './env';
import { Store } from './store';

const env = loadEnv();
const store = new Store(env.DATA_DIR);
const cas = createCasClient({
  baseUrl: env.CAS_ESIGN_BASE_URL,
  clientId: env.CAS_ESIGN_CLIENT_ID,
  apiKey: env.CAS_ESIGN_API_KEY,
  apiVersion: env.CAS_API_VERSION,
});

const app = await buildApp({ env, store, cas });

const retry = setInterval(() => app.signService.retryPendingDownloads(), 60_000);
const purge = setInterval(
  async () => {
    const removed = await store.purge(Date.now() - env.RETENTION_DAYS * 86_400_000);
    if (removed) app.log.info({ removed }, 'đã xoá yêu cầu ký cũ');
  },
  60 * 60_000,
);

app.addHook('onClose', async () => {
  clearInterval(retry);
  clearInterval(purge);
  store.close();
});

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.once(sig, () => void app.close().then(() => process.exit(0)));
}

await app.listen({ port: env.PORT, host: '0.0.0.0' });
app.log.info(`Webhook URL (khai báo ở CAS Console): <PUBLIC_URL>/webhooks/cas-sign?token=<CAS_WEBHOOK_TOKEN>`);
