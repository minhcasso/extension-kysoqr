import { buildApp } from './app';
import { createCasClient } from './cas-client';
import { loadEnv } from './env';

const env = loadEnv();
const cas = createCasClient({
  baseUrl: env.CAS_ESIGN_BASE_URL,
  clientId: env.CAS_ESIGN_CLIENT_ID,
  apiKey: env.CAS_ESIGN_API_KEY,
  apiVersion: env.CAS_API_VERSION,
});

const app = await buildApp({ env, cas });

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.once(sig, () => void app.close().then(() => process.exit(0)));
}

await app.listen({ port: env.PORT, host: '0.0.0.0' });
