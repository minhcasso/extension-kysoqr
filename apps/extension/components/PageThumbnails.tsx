import { useEffect, useRef, useState } from 'react';
import { AnnotationMode, type PDFDocumentProxy, type PDFPageProxy } from '../lib/pdf';
import { scrollWithin } from '../lib/scroll';

const THUMB_WIDTH = 140;

/** Ảnh thu nhỏ các trang (như trình xem PDF của Chrome): bấm để nhảy tới trang. */
export function PageThumbnails({
  doc,
  page,
  onJump,
  rotation = 0,
  annotations = true,
}: {
  doc: PDFDocumentProxy;
  /** Trang đang đọc. */
  page: number;
  onJump: (page: number) => void;
  /** Góc xoay thêm của trình xem (độ). */
  rotation?: number;
  annotations?: boolean;
}) {
  const listRef = useRef<HTMLOListElement>(null);

  // Trang đang đọc luôn nằm trong vùng nhìn thấy của danh sách.
  useEffect(() => {
    scrollWithin(listRef.current, listRef.current?.querySelector(`[data-thumb="${page}"]`), 'nearest');
  }, [page]);

  return (
    <ol className="thumbs" ref={listRef}>
      {Array.from({ length: doc.numPages }, (_, i) => i + 1).map((n) => (
        <Thumb
          key={n}
          doc={doc}
          pageNumber={n}
          active={n === page}
          rotation={rotation}
          annotations={annotations}
          onClick={() => onJump(n)}
        />
      ))}
    </ol>
  );
}

function Thumb({
  doc,
  pageNumber,
  active,
  rotation,
  annotations,
  onClick,
}: {
  doc: PDFDocumentProxy;
  pageNumber: number;
  active: boolean;
  rotation: number;
  annotations: boolean;
  onClick: () => void;
}) {
  const [page, setPage] = useState<PDFPageProxy | null>(null);
  const [visible, setVisible] = useState(false);
  const itemRef = useRef<HTMLLIElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    let cancelled = false;
    void doc.getPage(pageNumber).then((p) => !cancelled && setPage(p));
    return () => {
      cancelled = true;
    };
  }, [doc, pageNumber]);

  // Chỉ vẽ ảnh khi gần hiện ra trong danh sách.
  useEffect(() => {
    const el = itemRef.current;
    if (!el) return;
    const io = new IntersectionObserver(([e]) => e?.isIntersecting && setVisible(true), {
      rootMargin: '400px 0px',
    });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const angle = page ? (page.rotate + rotation) % 360 : 0;
  const base = page?.getViewport({ scale: 1, rotation: angle });
  const viewport = page && base ? page.getViewport({ scale: THUMB_WIDTH / base.width, rotation: angle }) : null;
  const height = viewport ? viewport.height : THUMB_WIDTH * 1.414;

  useEffect(() => {
    if (!page || !viewport || !visible || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(viewport.width * dpr);
    canvas.height = Math.floor(viewport.height * dpr);
    const task = page.render({
      canvasContext: canvas.getContext('2d')!,
      viewport,
      transform: dpr !== 1 ? [dpr, 0, 0, dpr, 0, 0] : undefined,
      annotationMode: annotations ? AnnotationMode.ENABLE : AnnotationMode.DISABLE,
    });
    task.promise.catch(() => {
      // bị huỷ khi đổi tài liệu / góc xoay
    });
    return () => task.cancel();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, visible, angle, annotations]);

  return (
    <li ref={itemRef} data-thumb={pageNumber}>
      <button
        type="button"
        className={`thumb ${active ? 'active' : ''}`}
        onClick={onClick}
        aria-label={`Trang ${pageNumber}`}
        aria-current={active ? 'page' : undefined}
      >
        <canvas ref={canvasRef} style={{ width: THUMB_WIDTH, height }} />
      </button>
      <span className="thumb-number">{pageNumber}</span>
    </li>
  );
}
