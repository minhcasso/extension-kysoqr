import { MAX_PDF_BYTES } from '@kysoqr/shared';

export interface PdfSource {
  bytes: Uint8Array;
  name: string;
}

export type SourceErrorKind = 'file-access' | 'permission' | 'not-pdf' | 'too-large' | 'fetch';

export class SourceError extends Error {
  constructor(
    readonly kind: SourceErrorKind,
    message: string,
    readonly origin?: string,
  ) {
    super(message);
  }
}

export interface Job {
  url: string;
  title: string;
}

export async function readJob(jobId: string | null): Promise<Job | undefined> {
  if (!jobId) return undefined;
  const key = `job:${jobId}`;
  const data = await browser.storage.session.get(key);
  return data[key] as Job | undefined;
}

export function validatePdf(bytes: Uint8Array, name: string): PdfSource {
  if (bytes.byteLength > MAX_PDF_BYTES) {
    throw new SourceError('too-large', 'File vượt quá 10MB, CAS chưa hỗ trợ.');
  }
  const head = new TextDecoder('latin1').decode(bytes.subarray(0, 1024));
  if (!head.includes('%PDF-')) {
    throw new SourceError('not-pdf', 'Tab hiện tại không phải file PDF.');
  }
  return { bytes, name };
}

function nameFromUrl(url: URL, fallback: string) {
  const last = decodeURIComponent(url.pathname.split('/').filter(Boolean).pop() ?? '');
  return last || fallback || 'document.pdf';
}

/** Tải PDF của tab gốc. Lỗi được phân loại để giao diện gợi ý cách khắc phục. */
export async function loadFromUrl(job: Job): Promise<PdfSource> {
  const url = new URL(job.url);
  const name = nameFromUrl(url, job.title);

  if (url.protocol === 'file:') {
    if (!(await browser.extension.isAllowedFileSchemeAccess())) {
      throw new SourceError('file-access', 'Extension chưa được phép đọc file trên máy.');
    }
  } else if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SourceError('not-pdf', 'Tab hiện tại không phải file PDF.');
  }

  if (url.protocol === 'file:') {
    return validatePdf(await readLocalFile(url.href), name);
  }

  let res: Response;
  try {
    res = await fetch(url, { credentials: 'include' });
  } catch {
    const granted = await browser.permissions.contains({ origins: [`${url.origin}/*`] });
    throw granted
      ? new SourceError('fetch', 'Không tải được file PDF từ trang này.')
      : new SourceError('permission', `Cần cấp quyền để tải file từ ${url.host}.`, url.origin);
  }
  if (!res.ok) {
    throw new SourceError('fetch', `Trang trả về lỗi ${res.status} khi tải file PDF.`);
  }
  return validatePdf(new Uint8Array(await res.arrayBuffer()), name);
}

/** fetch() không hỗ trợ file://; XMLHttpRequest thì đọc được khi extension có quyền truy cập file. */
function readLocalFile(url: string): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const fail = () => reject(new SourceError('fetch', 'Không đọc được file trên máy.'));
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url);
    xhr.responseType = 'arraybuffer';
    xhr.onload = () =>
      xhr.response && (xhr.status === 0 || xhr.status === 200)
        ? resolve(new Uint8Array(xhr.response as ArrayBuffer))
        : fail();
    xhr.onerror = fail;
    xhr.send();
  });
}

export async function loadFromFile(file: File): Promise<PdfSource> {
  return validatePdf(new Uint8Array(await file.arrayBuffer()), file.name);
}
