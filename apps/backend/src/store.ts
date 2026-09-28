import { mkdirSync } from 'node:fs';
import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { SignRequestState } from '@kysoqr/shared';

export interface SignRequestRow {
  signRequestId: string;
  accessTokenHash: string;
  documentName: string;
  state: SignRequestState;
  createdAt: number;
  expiresAt: number;
  signedAt: string | null;
  identityKey: string | null;
  identityKeyExpiresAt: string | null;
  orgIdSigned: string | null;
  filePath: string | null;
  downloadAttempts: number;
  lastSyncedAt: number;
}

export type SignRequestPatch = Partial<
  Pick<
    SignRequestRow,
    | 'state'
    | 'signedAt'
    | 'identityKey'
    | 'identityKeyExpiresAt'
    | 'orgIdSigned'
    | 'filePath'
    | 'downloadAttempts'
    | 'lastSyncedAt'
  >
>;

const COLUMNS: Record<keyof SignRequestRow, string> = {
  signRequestId: 'sign_request_id',
  accessTokenHash: 'access_token_hash',
  documentName: 'document_name',
  state: 'state',
  createdAt: 'created_at',
  expiresAt: 'expires_at',
  signedAt: 'signed_at',
  identityKey: 'identity_key',
  identityKeyExpiresAt: 'identity_key_expires_at',
  orgIdSigned: 'org_id_signed',
  filePath: 'file_path',
  downloadAttempts: 'download_attempts',
  lastSyncedAt: 'last_synced_at',
};

const SELECT = `SELECT ${Object.entries(COLUMNS)
  .map(([k, c]) => `${c} AS ${k}`)
  .join(', ')} FROM sign_requests`;

/** Lưu trạng thái yêu cầu ký (SQLite có sẵn trong Node) và file đã ký trên ổ đĩa. */
export class Store {
  private db: DatabaseSync;
  readonly filesDir: string;

  constructor(dataDir: string) {
    this.filesDir = join(dataDir, 'signed');
    mkdirSync(this.filesDir, { recursive: true });
    this.db = new DatabaseSync(join(dataDir, 'kysoqr.db'));
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sign_requests (
        sign_request_id TEXT PRIMARY KEY,
        access_token_hash TEXT NOT NULL,
        document_name TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        signed_at TEXT,
        identity_key TEXT,
        identity_key_expires_at TEXT,
        org_id_signed TEXT,
        file_path TEXT,
        download_attempts INTEGER NOT NULL DEFAULT 0,
        last_synced_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sign_requests_created ON sign_requests(created_at);
    `);
  }

  insert(row: Omit<SignRequestRow, 'signedAt' | 'identityKey' | 'identityKeyExpiresAt' | 'orgIdSigned' | 'filePath' | 'downloadAttempts'>) {
    this.db
      .prepare(
        `INSERT INTO sign_requests (sign_request_id, access_token_hash, document_name, state, created_at, expires_at, last_synced_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(row.signRequestId, row.accessTokenHash, row.documentName, row.state, row.createdAt, row.expiresAt, row.lastSyncedAt);
  }

  get(signRequestId: string): SignRequestRow | undefined {
    return this.db.prepare(`${SELECT} WHERE sign_request_id = ?`).get(signRequestId) as
      | SignRequestRow
      | undefined;
  }

  update(signRequestId: string, patch: SignRequestPatch) {
    const entries = Object.entries(patch).filter(([, v]) => v !== undefined);
    if (!entries.length) return;
    const sets = entries.map(([k]) => `${COLUMNS[k as keyof SignRequestRow]} = ?`).join(', ');
    this.db
      .prepare(`UPDATE sign_requests SET ${sets} WHERE sign_request_id = ?`)
      .run(...(entries.map(([, v]) => v) as (string | number | null)[]), signRequestId);
  }

  /** Các yêu cầu đã ký xong nhưng chưa tải được file (để thử lại). */
  pendingDownloads(maxAttempts: number): SignRequestRow[] {
    return this.db
      .prepare(
        `${SELECT} WHERE state = 'COMPLETED' AND file_path IS NULL AND identity_key IS NOT NULL AND download_attempts < ?`,
      )
      .all(maxAttempts) as unknown as SignRequestRow[];
  }

  async saveFile(signRequestId: string, pdf: Uint8Array): Promise<string> {
    const path = join(this.filesDir, `${signRequestId}.pdf`);
    await writeFile(path, pdf);
    return path;
  }

  /** Xoá bản ghi và file cũ hơn `olderThan` (ms epoch). */
  async purge(olderThan: number): Promise<number> {
    const rows = this.db
      .prepare(`${SELECT} WHERE created_at < ?`)
      .all(olderThan) as unknown as SignRequestRow[];
    for (const r of rows) {
      if (r.filePath) await rm(r.filePath, { force: true });
    }
    this.db.prepare('DELETE FROM sign_requests WHERE created_at < ?').run(olderThan);
    return rows.length;
  }

  close() {
    this.db.close();
  }
}
