import { useEffect, useLayoutEffect, useRef, useState, type MutableRefObject, type ReactNode } from 'react';
import type { PDFDocumentProxy } from '../lib/pdf';
import { scrollWithin } from '../lib/scroll';
import { PdfViewer } from './PdfViewer';

type ViewerProps = Omit<Parameters<typeof PdfViewer>[0], 'doc' | 'scale' | 'rotation'>;

export const MIN_SCALE = 0.25;
export const MAX_SCALE = 5;

export type FitMode = 'width' | 'page';

export interface DocumentControls {
  jump: (page: number) => void;
  /** Vừa khít khung xem theo `fitMode`: chiều ngang, hoặc cả trang. */
  fit: () => void;
  /** Trình chiếu: toàn màn hình, mỗi lần một trang (như "Present" của Chrome). */
  present: () => void;
}

/** Khoảng cách giữa 2 trang khi xem 2 trang (khớp `gap` của `.pages` trong CSS). */
const PAGE_GAP = 16;

/** Vùng xem PDF kiểu trình đọc thông thường: nền tối, các trang xếp dọc, Ctrl + cuộn để zoom. */
export function DocumentView({
  doc,
  scale,
  onScale,
  onZoom,
  onPageChange,
  controlsRef,
  autoFit,
  fitMode,
  rotation,
  twoPage = false,
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
  fitMode: FitMode;
  /** Góc xoay thêm (độ), chỉ để xem: không đổi file gửi ký. */
  rotation: number;
  empty?: ReactNode;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const ratio = useRef(0);
  /** Kích thước trang 1 ở tỷ lệ 1, đã tính góc xoay. */
  const pageSize = useRef<{ width: number; height: number } | null>(null);
  const currentPage = useRef(1);
  const [presenting, setPresenting] = useState(false);
  /** Tỷ lệ trước khi trình chiếu, để trả lại khi thoát. */
  const scaleBeforePresent = useRef<number | null>(null);

  // Khi trình chiếu: luôn vừa trang, một trang mỗi màn hình.
  const mode: FitMode = presenting ? 'page' : fitMode;
  const columns = twoPage && !presenting ? 2 : 1;

  const fit = () => {
    const el = scrollRef.current;
    const size = pageSize.current;
    if (!el || !size) return;
    const width = size.width * columns + PAGE_GAP * (columns - 1);
    let next: number;
    if (mode === 'page') {
      // Cả trang nằm gọn trong khung (như "Vừa trang" của Chrome).
      const pad = presenting ? 0 : 32;
      next = Math.min((el.clientWidth - pad * 2) / width, (el.clientHeight - pad) / size.height);
    } else {
      // Vừa khít chiều ngang nhưng không để trang to quá (như trình xem PDF của Chrome).
      const avail = Math.min(el.clientWidth - 64, 1000 * columns);
      next = Math.min(1.5, Math.max(0.5, avail / width));
    }
    onScale(Math.round(Math.min(MAX_SCALE, Math.max(MIN_SCALE, next)) * 100) / 100);
  };
  // ResizeObserver giữ tham chiếu tới bản `fit` mới nhất (theo fitMode hiện tại).
  const fitRef = useRef(fit);
  fitRef.current = fit;

  const measure = async (d: PDFDocumentProxy) => {
    const p = await d.getPage(1);
    const vp = p.getViewport({ scale: 1, rotation: (p.rotate + rotation) % 360 });
    return { width: vp.width, height: vp.height };
  };

  useEffect(() => {
    pageSize.current = null;
    if (!doc) return;
    let cancelled = false;
    void measure(doc).then((size) => {
      if (cancelled) return;
      pageSize.current = size;
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

  // Xoay trang, đổi chế độ vừa khít hoặc xem 2 trang → đo lại và vừa khít lại (nếu chưa zoom tay).
  useEffect(() => {
    if (!doc || !pageSize.current) return;
    let cancelled = false;
    void measure(doc).then((size) => {
      if (cancelled) return;
      pageSize.current = size;
      if (autoFit || presenting) fitRef.current();
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rotation, fitMode, autoFit, twoPage, presenting]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !(autoFit || presenting)) return;
    const ro = new ResizeObserver(() => fitRef.current());
    ro.observe(el);
    return () => ro.disconnect();
  }, [autoFit, presenting]);

  // Vào/thoát toàn màn hình (Esc do trình duyệt xử lý).
  useEffect(() => {
    const onChange = () => {
      const on = document.fullscreenElement === scrollRef.current && scrollRef.current !== null;
      setPresenting(on);
      if (!on && scaleBeforePresent.current !== null) {
        const page = currentPage.current;
        onScale(scaleBeforePresent.current);
        scaleBeforePresent.current = null;
        // Chờ trang vẽ lại theo tỷ lệ cũ rồi quay về đúng trang đang chiếu.
        requestAnimationFrame(() => controlsRef.current?.jump(page));
      }
    };
    document.addEventListener('fullscreenchange', onChange);
    return () => document.removeEventListener('fullscreenchange', onChange);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Trình chiếu: ←/→, PageUp/PageDown, Space để chuyển trang.
  useEffect(() => {
    if (!presenting || !doc) return;
    const onKey = (e: KeyboardEvent) => {
      const next = ['ArrowRight', 'ArrowDown', 'PageDown', ' '].includes(e.key)
        ? 1
        : ['ArrowLeft', 'ArrowUp', 'PageUp'].includes(e.key)
          ? -1
          : 0;
      if (!next) return;
      e.preventDefault();
      const page = Math.min(doc.numPages, Math.max(1, currentPage.current + next));
      controlsRef.current?.jump(page);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presenting, doc]);

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
      scrollWithin(
        scrollRef.current,
        scrollRef.current?.querySelector(`[data-page="${page}"]`),
        'start',
      ),
    fit,
    present: () => {
      const el = scrollRef.current;
      if (!el || !doc || document.fullscreenElement) return;
      scaleBeforePresent.current = scale;
      const page = currentPage.current;
      void el.requestFullscreen().then(
        () => requestAnimationFrame(() => controlsRef.current?.jump(page)),
        () => {
          scaleBeforePresent.current = null;
        },
      );
    },
  };

  function onScroll() {
    const el = scrollRef.current;
    if (!el) return;
    ratio.current = el.scrollHeight ? el.scrollTop / el.scrollHeight : 0;
    const line = el.getBoundingClientRect().top + el.clientHeight * (presenting ? 0.5 : 0.35);
    for (const wrap of el.querySelectorAll<HTMLElement>('[data-page]')) {
      const r = wrap.getBoundingClientRect();
      if (r.top <= line && r.bottom >= line) {
        currentPage.current = Number(wrap.dataset.page);
        onPageChange(currentPage.current);
        break;
      }
    }
  }

  return (
    <div
      className={`doc-scroll ${presenting ? 'presenting' : ''}`}
      ref={scrollRef}
      onScroll={onScroll}
      tabIndex={-1}
    >
      {doc && scale ? (
        <PdfViewer
          doc={doc}
          scale={scale}
          rotation={rotation}
          {...viewer}
          twoPage={columns === 2}
          // Trình chiếu chỉ để xem: ẩn các ô ký đang đặt.
          fields={presenting ? [] : viewer.fields}
        />
      ) : (
        empty
      )}
    </div>
  );
}
