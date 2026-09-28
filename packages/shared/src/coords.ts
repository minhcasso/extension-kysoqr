/**
 * Quy đổi giữa ô ký vẽ trên màn hình (pixel của PDF.js viewport) và tỉ lệ mà CAS ID
 * `signatureFields` yêu cầu: gốc ở góc dưới-trái trang, 0..1, x+w ≤ 1, y+h ≤ 1.
 *
 * Hàm thuần: nhận `transform` (viewport.transform của PDF.js) và `view` (page.view =
 * [x0, y0, x1, y1] trong PDF user space) để test được mà không cần PDF.js.
 *
 * Tỉ lệ được tính trên hệ trục CHƯA xoay của trang (user space), nên trang có /Rotate
 * vẫn cho kết quả ổn định. Cần CAS xác nhận họ dùng CropBox (page.view) và bỏ qua /Rotate.
 */

export type Transform = readonly [number, number, number, number, number, number];
export type PageView = readonly [number, number, number, number];

/** Hình chữ nhật trên viewport, đơn vị pixel CSS, gốc góc trên-trái. */
export interface ViewportBox {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface FieldRatios {
  xRatio: number;
  yRatio: number;
  widthRatio: number;
  heightRatio: number;
}

const PRECISION = 1e6;

function applyTransform(x: number, y: number, m: Transform): [number, number] {
  return [m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]];
}

function applyInverseTransform(x: number, y: number, m: Transform): [number, number] {
  const d = m[0] * m[3] - m[1] * m[2];
  return [
    (x * m[3] - y * m[2] + m[2] * m[5] - m[4] * m[3]) / d,
    (-x * m[1] + y * m[0] + m[4] * m[1] - m[5] * m[0]) / d,
  ];
}

const clamp01 = (v: number) => Math.min(1, Math.max(0, v));
const floorP = (v: number) => Math.floor(v * PRECISION) / PRECISION;
const roundP = (v: number) => Math.round(v * PRECISION) / PRECISION;

/** Ô ký trên màn hình → tỉ lệ gửi cho CAS. */
export function viewportBoxToRatios(box: ViewportBox, transform: Transform, view: PageView): FieldRatios {
  const [x0, y0, x1, y1] = view;
  const pageW = x1 - x0;
  const pageH = y1 - y0;

  const corners = [
    applyInverseTransform(box.left, box.top, transform),
    applyInverseTransform(box.left + box.width, box.top + box.height, transform),
  ];
  const xs = corners.map((c) => c[0]);
  const ys = corners.map((c) => c[1]);

  const minX = clamp01((Math.min(...xs) - x0) / pageW);
  const maxX = clamp01((Math.max(...xs) - x0) / pageW);
  const minY = clamp01((Math.min(...ys) - y0) / pageH);
  const maxY = clamp01((Math.max(...ys) - y0) / pageH);

  const xRatio = roundP(minX);
  const yRatio = roundP(minY);
  // Làm tròn xuống để x+w và y+h không vượt quá 1 sau khi làm tròn.
  return {
    xRatio,
    yRatio,
    widthRatio: floorP(Math.min(maxX - minX, 1 - xRatio)),
    heightRatio: floorP(Math.min(maxY - minY, 1 - yRatio)),
  };
}

/** Tỉ lệ đã lưu → ô trên màn hình (dùng khi zoom/render lại). */
export function ratiosToViewportBox(r: FieldRatios, transform: Transform, view: PageView): ViewportBox {
  const [x0, y0, x1, y1] = view;
  const pageW = x1 - x0;
  const pageH = y1 - y0;

  const a = applyTransform(x0 + r.xRatio * pageW, y0 + r.yRatio * pageH, transform);
  const b = applyTransform(
    x0 + (r.xRatio + r.widthRatio) * pageW,
    y0 + (r.yRatio + r.heightRatio) * pageH,
    transform,
  );
  return {
    left: Math.min(a[0], b[0]),
    top: Math.min(a[1], b[1]),
    width: Math.abs(b[0] - a[0]),
    height: Math.abs(b[1] - a[1]),
  };
}
