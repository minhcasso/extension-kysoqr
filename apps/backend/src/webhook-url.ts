// In URL webhook đầy đủ để dán vào CAS Console (console.bankhub.dev → Webhook → SIGN).
import { loadEnv } from './env';

const env = loadEnv();
if (!env.CAS_WEBHOOK_TOKEN) {
  console.error('Thiếu CAS_WEBHOOK_TOKEN trong apps/backend/.env. Tạo bằng: openssl rand -hex 32');
  process.exit(1);
}
if (!env.PUBLIC_URL) {
  console.error('Thiếu PUBLIC_URL trong apps/backend/.env (domain backend hoặc URL ngrok, vd https://xxxx.ngrok-free.app).');
  process.exit(1);
}
console.log(`${env.PUBLIC_URL}/webhooks/cas-sign?token=${env.CAS_WEBHOOK_TOKEN}`);
