import { useEffect, useLayoutEffect, useRef, type MutableRefObject, type ReactNode } from 'react';
import type { PDFDocumentProxy } from '../lib/pdf';
import { PdfViewer } from './PdfViewer';

type ViewerProps = Omit<Parameters<typeof PdfViewer>[0], 'doc' | 'scale'>;

export const MIN_SCALE = 0.25;
export const MAX_SCALE = 5;

export interface DocumentControls {
  jump: (page: number) => void;
  /** Vừa khít chiều ngang khung xem. */
  fit: () => void;
}

/** Vùng xem PDF kiểu trình đọc thông thường: nền tối, các trang xếp dọc, Ctrl + cuộn để zoom. */
export function DocumentView({
  doc,
  scale,
  onScale,
  onZoom,
  onPageChange,
  controlsRef,
  autoFit,
  empty,
  ...viewer
}: ViewerProps & {
  doc: PDFDocumentProxy | null;
  scale: number | null;
  /** Đặt tỷ lệ tự động (mở tài liệu, vừa khít). */
  onScale: (scale: number) => void;
  /** Người dùng zoom (Ctrl + cuộn). */
  onZoom: (factor: number) => void;
  onPageChange: (page: number) => void;
  controlsRef: MutableRefObject<DocumentControls | null>;
  /** Chưa zoom tay: tự vừa khít lại khi khung đổi kích thước (mở/đóng bảng bên). */
  autoFit: boolean;
  empty?: ReactNode;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const ratio = useRef(0);
  const pageWidth = useRef<number | null>(null);

  const fit = () => {
    const el = scrollRef.current;
    if (!el || !pageWidth.current) return;
    // Vừa khít chiều ngang nhưng không để trang to quá (như trình xem PDF của Chrome).
    const width = Math.min(el.clientWidth - 64, 1000);
    onScale(Math.round(Math.min(1.5, Math.max(0.5, width / pageWidth.current)) * 100) / 100);
  };

  useEffect(() => {
    pageWidth.current = null;
    if (!doc) return;
    let cancelled = false;
    void doc.getPage(1).then((p) => {
      if (cancelled) return;
      pageWidth.current = p.getViewport({ scale: 1 }).width;
      ratio.current = 0;
      fit();
      // Để phím PageUp/PageDown/Home/End cuộn tài liệu ngay như trình xem PDF.
      scrollRef.current?.focus({ preventScroll: true });
      onPageChange(1);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [doc]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !autoFit) return;
    const ro = new ResizeObserver(() => fit());
    ro.observe(el);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoFit]);

  // Ctrl/⌘ + cuộn chuột để zoom như Chrome (cần listener không passive để chặn zoom cả trang).
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      onZoom(e.deltaY < 0 ? 1.1 : 1 / 1.1);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [onZoom]);

  // Giữ nguyên vị trí đang đọc khi đổi zoom.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = ratio.current * el.scrollHeight;
  }, [scale]);

  controlsRef.current = {
    jump: (page) =>
      scrollRef.current?.querySelector(`[data-page="${page}"]`)?.scrollIntoView({ block: 'start' }),
    fit,
  };

  function onScroll() {
    const el = scrollRef.current;
    if (!el) return;
    ratio.current = el.scrollHeight ? el.scrollTop / el.scrollHeight : 0;
    const line = el.getBoundingClientRect().top + el.clientHeight * 0.35;
    for (const wrap of el.querySelectorAll<HTMLElement>('[data-page]')) {
      const r = wrap.getBoundingClientRect();
      if (r.top <= line && r.bottom >= line) {
        onPageChange(Number(wrap.dataset.page));
        break;
      }
    }
  }

  return (
    <div className="doc-scroll" ref={scrollRef} onScroll={onScroll} tabIndex={-1}>
      {doc && scale ? <PdfViewer doc={doc} scale={scale} {...viewer} /> : empty}
    </div>
  );
}
