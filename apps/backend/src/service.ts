import { isTerminalState, type SignRequestState } from '@kysoqr/shared';
import type { FastifyBaseLogger } from 'fastify';
import type { CasClient } from './cas-client';
import type { SignRequestRow, Store } from './store';

/** identityKey dùng được tối đa 5 lần; giữ lại 2 lần dự phòng để xử lý tay nếu cần. */
export const MAX_DOWNLOAD_ATTEMPTS = 3;
/** Không hỏi CAS request-status quá 1 lần mỗi khoảng này cho cùng một yêu cầu. */
const SYNC_INTERVAL_MS = 4_000;

export interface CasUpdate {
  state: SignRequestState;
  signedAt?: string | null;
  identityKey?: string | null;
  identityKeyExpiresAt?: string | null;
  orgIdSigned?: string | null;
}

export class SignService {
  private downloads = new Map<string, Promise<void>>();

  constructor(
    private store: Store,
    private cas: CasClient,
    private log: FastifyBaseLogger,
    private now: () => number = Date.now,
  ) {}

  /** Ghi nhận cập nhật từ webhook hoặc request-status. Không lùi trạng thái đã kết thúc. */
  applyUpdate(row: SignRequestRow, update: CasUpdate): SignRequestRow {
    const state =
      isTerminalState(row.state) && row.state !== update.state ? row.state : update.state;
    this.store.update(row.signRequestId, {
      state,
      signedAt: update.signedAt ?? undefined,
      identityKey: update.identityKey ?? undefined,
      identityKeyExpiresAt: update.identityKeyExpiresAt ?? undefined,
      orgIdSigned: update.orgIdSigned ?? undefined,
      lastSyncedAt: this.now(),
    });
    const next = this.store.get(row.signRequestId)!;
    if (next.state === 'COMPLETED') void this.ensureDownloaded(next.signRequestId);
    return next;
  }

  /** Hỏi CAS nếu webhook chưa về và lần hỏi trước đã lâu. */
  async syncIfStale(row: SignRequestRow): Promise<SignRequestRow> {
    if (isTerminalState(row.state) || this.now() - row.lastSyncedAt < SYNC_INTERVAL_MS) return row;
    if (this.now() > row.expiresAt) return row;
    try {
      const s = await this.cas.requestStatus(row.signRequestId);
      return this.applyUpdate(row, s);
    } catch (err) {
      this.log.warn({ err, signRequestId: row.signRequestId }, 'request-status thất bại');
      this.store.update(row.signRequestId, { lastSyncedAt: this.now() });
      return row;
    }
  }

  /** Tải file đã ký về đúng một lần (idempotent giữa webhook, polling và job thử lại). */
  ensureDownloaded(signRequestId: string): Promise<void> {
    const inflight = this.downloads.get(signRequestId);
    if (inflight) return inflight;
    const p = this.download(signRequestId).finally(() => this.downloads.delete(signRequestId));
    this.downloads.set(signRequestId, p);
    return p;
  }

  private async download(signRequestId: string) {
    const row = this.store.get(signRequestId);
    if (!row || row.filePath || !row.identityKey) return;
    if (row.downloadAttempts >= MAX_DOWNLOAD_ATTEMPTS) return;
    if (row.identityKeyExpiresAt && Date.parse(row.identityKeyExpiresAt) < this.now()) {
      this.log.error({ signRequestId }, 'identityKey đã hết hạn trước khi tải được file');
      return;
    }
    this.store.update(signRequestId, { downloadAttempts: row.downloadAttempts + 1 });
    try {
      const pdf = await this.cas.downloadFile(row.identityKey);
      if (!isPdf(pdf)) throw new Error('download-file không trả về PDF');
      const filePath = await this.store.saveFile(signRequestId, pdf);
      this.store.update(signRequestId, { filePath });
      this.log.info({ signRequestId, bytes: pdf.byteLength }, 'đã lưu file đã ký');
    } catch (err) {
      this.log.error({ err, signRequestId, attempt: row.downloadAttempts + 1 }, 'tải file đã ký thất bại');
    }
  }

  private syncing = false;

  /**
   * Chạy mỗi 5 giây: hỏi CAS trạng thái mọi yêu cầu đang chờ, để file đã ký được tải về
   * kể cả khi webhook không tới và người dùng đã đóng tab.
   */
  async syncActive() {
    if (this.syncing) return;
    this.syncing = true;
    try {
      for (const row of this.store.activeRequests(this.now())) {
        await this.syncIfStale(row);
      }
      this.retryPendingDownloads();
    } finally {
      this.syncing = false;
    }
  }

  retryPendingDownloads() {
    for (const row of this.store.pendingDownloads(MAX_DOWNLOAD_ATTEMPTS)) {
      void this.ensureDownloaded(row.signRequestId);
    }
  }
}

function isPdf(bytes: Uint8Array) {
  return (
    bytes.length > 4 &&
    bytes[0] === 0x25 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x44 &&
    bytes[3] === 0x46
  );
}
