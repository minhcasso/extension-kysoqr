import * as pdfjs from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';

// Worker đóng gói trong extension: CSP của MV3 không cho tải script từ CDN.
pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

export type { PDFDocumentProxy, PDFPageProxy, PageViewport } from 'pdfjs-dist';

/** Lớp chữ trong suốt phủ lên trang, để bôi đen / sao chép chữ như trình xem PDF thông thường. */
export const TextLayer = pdfjs.TextLayer;

export function openPdf(bytes: Uint8Array) {
  // PDF.js chiếm (detach) buffer được truyền vào, nên đưa bản sao để giữ bản gốc gửi lên CAS.
  return pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false }).promise;
}

export const isPasswordError = (err: unknown) =>
  err instanceof Error && err.name === 'PasswordException';
