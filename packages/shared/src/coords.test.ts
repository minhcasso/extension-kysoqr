import { describe, expect, it } from 'vitest';
import { ratiosToViewportBox, viewportBoxToRatios, type PageView, type Transform } from './coords';

/** Tái tạo PageViewport.transform của PDF.js (display_utils.js) để test không cần PDF.js. */
function viewportTransform(view: PageView, scale: number, rotation: 0 | 90 | 180 | 270): Transform {
  const [x0, y0, x1, y1] = view;
  const cx = (x1 + x0) / 2;
  const cy = (y1 + y0) / 2;
  const [a, b, c, d] = {
    0: [1, 0, 0, -1],
    90: [0, 1, 1, 0],
    180: [-1, 0, 0, 1],
    270: [0, -1, -1, 0],
  }[rotation] as [number, number, number, number];
  const offX = a === 0 ? Math.abs(cy - y0) * scale : Math.abs(cx - x0) * scale;
  const offY = a === 0 ? Math.abs(cx - x0) * scale : Math.abs(cy - y0) * scale;
  return [
    a * scale,
    b * scale,
    c * scale,
    d * scale,
    offX - a * scale * cx - c * scale * cy,
    offY - b * scale * cx - d * scale * cy,
  ];
}

const A4: PageView = [0, 0, 595, 842];

describe('viewportBoxToRatios', () => {
  it('trang A4 không xoay: gốc dưới-trái', () => {
    const t = viewportTransform(A4, 1, 0);
    // Ô ở góc trên-trái màn hình → yRatio gần 1 - height.
    const r = viewportBoxToRatios({ left: 0, top: 0, width: 119, height: 84.2 }, t, A4);
    expect(r.xRatio).toBeCloseTo(0);
    expect(r.widthRatio).toBeCloseTo(0.2);
    expect(r.heightRatio).toBeCloseTo(0.1);
    expect(r.yRatio).toBeCloseTo(0.9);
  });

  it('không phụ thuộc zoom', () => {
    const box = { left: 100, top: 200, width: 150, height: 60 };
    const r1 = viewportBoxToRatios(box, viewportTransform(A4, 1, 0), A4);
    const r2 = viewportBoxToRatios(
      { left: 200, top: 400, width: 300, height: 120 },
      viewportTransform(A4, 2, 0),
      A4,
    );
    expect(r2).toEqual(r1);
  });

  it('CropBox lệch gốc', () => {
    const view: PageView = [50, 100, 645, 942];
    const t = viewportTransform(view, 1.5, 0);
    const r = viewportBoxToRatios({ left: 0, top: 0, width: 595 * 1.5, height: 842 * 1.5 }, t, view);
    expect(r).toEqual({ xRatio: 0, yRatio: 0, widthRatio: 1, heightRatio: 1 });
  });

  it.each([90, 180, 270] as const)('trang xoay %i°: ô ở góc trên-trái màn hình', (rot) => {
    const t = viewportTransform(A4, 1, rot);
    const r = viewportBoxToRatios({ left: 0, top: 0, width: 10, height: 10 }, t, A4);
    // Góc trên-trái màn hình ứng với các góc khác nhau của trang chưa xoay.
    const expected = {
      90: { x: 0, y: 0 },
      180: { x: 1 - 10 / 595, y: 0 },
      270: { x: 1 - 10 / 595, y: 1 - 10 / 842 },
    }[rot];
    expect(r.xRatio).toBeCloseTo(expected.x, 5);
    expect(r.yRatio).toBeCloseTo(expected.y, 5);
  });

  it('ô tràn ra ngoài trang bị cắt và luôn thỏa x+w ≤ 1, y+h ≤ 1', () => {
    const t = viewportTransform(A4, 1, 0);
    const r = viewportBoxToRatios({ left: 500, top: -50, width: 300, height: 200 }, t, A4);
    expect(r.xRatio + r.widthRatio).toBeLessThanOrEqual(1);
    expect(r.yRatio + r.heightRatio).toBeLessThanOrEqual(1);
    expect(r.yRatio + r.heightRatio).toBeCloseTo(1, 5);
  });
});

describe('ratiosToViewportBox', () => {
  it.each([0, 90, 180, 270] as const)('đi và về khớp nhau khi xoay %i°', (rot) => {
    const t = viewportTransform(A4, 1.25, rot);
    const box = { left: 40, top: 70, width: 120, height: 50 };
    const back = ratiosToViewportBox(viewportBoxToRatios(box, t, A4), t, A4);
    expect(back.left).toBeCloseTo(box.left, 2);
    expect(back.top).toBeCloseTo(box.top, 2);
    expect(back.width).toBeCloseTo(box.width, 2);
    expect(back.height).toBeCloseTo(box.height, 2);
  });
});
