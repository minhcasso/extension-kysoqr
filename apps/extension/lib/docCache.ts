/**
 * Giữ tài liệu đang xem khi tải lại trang (F5), như trình xem PDF của Chrome.
 *
 * File (kể cả file chọn từ máy, kéo thả, hay bản vừa ký) được lưu tạm vào IndexedDB của
 * extension; mã của nó nằm trong sessionStorage của tab — còn khi tải lại, mất khi đóng tab.
 * Chỉ giữ vài bản gần nhất và xoá bản cũ quá 1 ngày, nên không đầy dần theo thời gian.
 */

export interface CachedDoc {
  name: string;
  bytes: Uint8Array;
  originalUrl?: string;
}

interface Row extends Omit<CachedDoc, 'bytes'> {
  id: string;
  blob: Blob;
  savedAt: number;
}

const DB_NAME = 'kysoqr';
const STORE = 'docs';
const TAB_KEY = 'kysoqr.docId';
const MAX_DOCS = 5;
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'id' });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function run<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const req = fn(tx.objectStore(STORE));
        tx.oncomplete = () => {
          db.close();
          resolve(req.result);
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      }),
  );
}

function tabDocId(): string | null {
  try {
    return sessionStorage.getItem(TAB_KEY);
  } catch {
    return null;
  }
}

/** Lưu tài liệu tab đang xem (ghi đè bản trước của cùng tab). Lỗi lưu không ảnh hưởng việc xem. */
export async function saveTabDoc(doc: CachedDoc): Promise<void> {
  try {
    let id = tabDocId();
    if (!id) {
      id = crypto.randomUUID();
      sessionStorage.setItem(TAB_KEY, id);
    }
    const row: Row = {
      id,
      name: doc.name,
      originalUrl: doc.originalUrl,
      blob: new Blob([doc.bytes.slice()], { type: 'application/pdf' }),
      savedAt: Date.now(),
    };
    await run('readwrite', (s) => s.put(row));
    await prune(id);
  } catch (e) {
    console.warn('[KysoQR] không lưu tạm được tài liệu', e);
  }
}

/** Tài liệu tab này đang xem trước khi tải lại trang (nếu có). */
export async function loadTabDoc(): Promise<CachedDoc | null> {
  const id = tabDocId();
  if (!id) return null;
  try {
    const row = await run<Row | undefined>('readonly', (s) => s.get(id));
    if (!row) return null;
    return {
      name: row.name,
      originalUrl: row.originalUrl,
      bytes: new Uint8Array(await row.blob.arrayBuffer()),
    };
  } catch {
    return null;
  }
}

/** Xoá bản quá cũ và chỉ giữ vài bản mới nhất (các tab đã đóng không tự dọn được). */
async function prune(keepId: string) {
  const rows = await run<Row[]>('readonly', (s) => s.getAll());
  const now = Date.now();
  const stale = rows
    .filter((r) => r.id !== keepId)
    .sort((a, b) => b.savedAt - a.savedAt)
    .filter((r, i) => i >= MAX_DOCS - 1 || now - r.savedAt > MAX_AGE_MS);
  for (const r of stale) await run('readwrite', (s) => s.delete(r.id));
}
