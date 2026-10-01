import type { PDFDocumentProxy } from './pdf';

/** Độ phân giải khi in (như trình xem pdf.js): đủ nét cho chữ, không quá nặng bộ nhớ. */
const PRINT_DPI = 150;

let printing = false;

/**
 * In tài liệu như trình xem PDF của Chrome: vẽ từng trang (theo hướng gốc, không theo góc xoay
 * khi xem) thành ảnh, đặt vào một khung chỉ hiện khi in, rồi mở hộp thoại in của trình duyệt.
 */
export async function printPdf(
  doc: PDFDocumentProxy,
  onProgress?: (done: number, total: number) => void,
): Promise<void> {
  if (printing) return;
  printing = true;
  const urls: string[] = [];
  const container = document.createElement('div');
  container.id = 'print-container';
  try {
    for (let n = 1; n <= doc.numPages; n++) {
      const page = await doc.getPage(n);
      const viewport = page.getViewport({ scale: PRINT_DPI / 72 });
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(viewport.width);
      canvas.height = Math.floor(viewport.height);
      const ctx = canvas.getContext('2d')!;
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      await page.render({ canvasContext: ctx, viewport, intent: 'print' }).promise;
      const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r));
      if (!blob) throw new Error('Không tạo được ảnh trang để in.');
      const url = URL.createObjectURL(blob);
      urls.push(url);
      const wrap = document.createElement('div');
      wrap.className = 'print-page';
      const img = document.createElement('img');
      img.src = url;
      wrap.append(img);
      container.append(wrap);
      onProgress?.(n, doc.numPages);
    }
    document.body.append(container);
    // Chờ ảnh giải mã xong, nếu không trang in có thể bị trắng.
    await Promise.all(Array.from(container.querySelectorAll('img'), (img) => img.decode()));
    await new Promise<void>((resolve) => {
      window.addEventListener('afterprint', () => resolve(), { once: true });
      window.print();
    });
  } finally {
    container.remove();
    urls.forEach((u) => URL.revokeObjectURL(u));
    printing = false;
  }
}
