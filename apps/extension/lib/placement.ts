import {
  ratiosToViewportBox,
  viewportBoxToRatios,
  type PageView as PageBox,
  type Transform,
  type ViewportBox,
} from '@kysoqr/shared';
import type { Field } from '../components/PdfViewer';
import type { PDFDocumentProxy } from './pdf';

/** Kích thước ô ký mặc định, đơn vị điểm PDF (1/72 inch). */
export const DEFAULT_BOX = { width: 200, height: 80 };

const overlaps = (a: ViewportBox, b: ViewportBox) =>
  a.left < b.left + b.width &&
  b.left < a.left + a.width &&
  a.top < b.top + b.height &&
  b.top < a.top + a.height;

/**
 * Ô chữ ký đặt sẵn khi bấm "Ký": gần cuối trang đang đọc (chỗ ký thường nằm), lệch phải.
 * Tránh đè lên ô chữ ký đã có trong PDF và ô người dùng đã đặt; hết chỗ thì dịch dần lên trên.
 */
export async function defaultField(
  pdf: PDFDocumentProxy,
  pageNumber: number,
  existing: Field[],
): Promise<Field> {
  const page = await pdf.getPage(pageNumber);
  const viewport = page.getViewport({ scale: 1 });
  const transform = viewport.transform as unknown as Transform;
  const view = page.view as unknown as PageBox;

  const taken: ViewportBox[] = existing
    .filter((f) => f.page === pageNumber)
    .map((f) => ratiosToViewportBox(f.ratios, transform, view));
  try {
    for (const a of await page.getAnnotations()) {
      if (a.fieldType !== 'Sig' || !Array.isArray(a.rect)) continue;
      const [x1, y1, x2, y2] = viewport.convertToViewportRectangle(a.rect);
      taken.push({
        left: Math.min(x1, x2),
        top: Math.min(y1, y2),
        width: Math.abs(x2 - x1),
        height: Math.abs(y2 - y1),
      });
    }
  } catch {
    // không đọc được annotation → chỉ tránh các ô đã đặt
  }

  const w = Math.min(DEFAULT_BOX.width, viewport.width * 0.8);
  const h = Math.min(DEFAULT_BOX.height, viewport.height * 0.3);
  const marginX = viewport.width * 0.08;
  const bottom = viewport.height * 0.1;
  const columns = [viewport.width - marginX - w, marginX, (viewport.width - w) / 2];

  let box: ViewportBox = {
    left: columns[0]!,
    top: viewport.height - bottom - h,
    width: w,
    height: h,
  };
  search: for (let top = box.top; top >= viewport.height * 0.35; top -= h + 12) {
    for (const left of columns) {
      const candidate = { left, top, width: w, height: h };
      if (!taken.some((t) => overlaps(t, candidate))) {
        box = candidate;
        break search;
      }
    }
  }

  return {
    id: crypto.randomUUID(),
    page: pageNumber,
    fieldType: 'SIGNATURE',
    ratios: viewportBoxToRatios(box, transform, view),
  };
}
