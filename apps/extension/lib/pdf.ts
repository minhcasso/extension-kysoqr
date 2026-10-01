import * as pdfjs from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';

// Worker đóng gói trong extension: CSP của MV3 không cho tải script từ CDN.
pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

// Khởi động worker ngay khi trang mở (song song với lúc tải file), dùng chung cho mọi tài liệu.
const worker = new pdfjs.PDFWorker();

export type { PDFDocumentProxy, PDFPageProxy, PageViewport } from 'pdfjs-dist';

/** Lớp chữ trong suốt phủ lên trang, để bôi đen / sao chép chữ như trình xem PDF thông thường. */
export const TextLayer = pdfjs.TextLayer;

/** Bật/tắt vẽ chú thích (annotation) — kể cả hình chữ ký hiển thị trên trang. */
export const AnnotationMode = pdfjs.AnnotationMode;

/** Đọc ngày kiểu PDF ("D:20260930...") trong thuộc tính tài liệu. */
export const PDFDateString = pdfjs.PDFDateString;

export function openPdf(bytes: Uint8Array) {
  // PDF.js chiếm (detach) buffer được truyền vào, nên đưa bản sao để giữ bản gốc gửi lên CAS.
  return pdfjs.getDocument({ data: bytes.slice(), worker, isEvalSupported: false }).promise;
}

export const isPasswordError = (err: unknown) =>
  err instanceof Error && err.name === 'PasswordException';
