import { z } from 'zod';

const list = z
  .string()
  .default('')
  .transform((s) =>
    s
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean),
  );

const Env = z.object({
  CAS_ESIGN_BASE_URL: z.string().url(),
  CAS_ESIGN_CLIENT_ID: z.string().min(1),
  CAS_ESIGN_API_KEY: z.string().min(1),
  CAS_API_VERSION: z.string().default('2023-01-01'),
  PORT: z.coerce.number().int().default(8787),
  EXTENSION_ORIGINS: list,
});
export type Env = z.infer<typeof Env>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = Env.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Cấu hình .env không hợp lệ:\n${issues}`);
  }
  return parsed.data;
}
