import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { PDFDocumentProxy } from '../lib/pdf';
import { PdfViewer } from './PdfViewer';

type ViewerProps = Omit<Parameters<typeof PdfViewer>[0], 'doc' | 'scale'>;

/** Vùng cuộn chứa tài liệu + thanh zoom; tự vừa chiều ngang khi mở. */
export function DocumentView({
  doc,
  toolbar,
  ...viewer
}: ViewerProps & { doc: PDFDocumentProxy; toolbar?: ReactNode }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    void doc.getPage(1).then((p) => {
      if (cancelled || !scrollRef.current) return;
      const width = p.getViewport({ scale: 1 }).width;
      const available = scrollRef.current.clientWidth - 64;
      setScale(Math.min(1.6, Math.max(0.5, available / width)));
    });
    return () => {
      cancelled = true;
    };
  }, [doc]);

  const zoom = (factor: number) =>
    setScale((s) => (s ? Math.round(Math.min(3, Math.max(0.4, s * factor)) * 100) / 100 : s));

  return (
    <div className="doc">
      <div className="doc-toolbar">
        {toolbar}
        <div className="spacer" />
        <button type="button" className="ghost" onClick={() => zoom(1 / 1.2)} title="Thu nhỏ">
          −
        </button>
        <span className="zoom-value">{scale ? Math.round(scale * 100) : 100}%</span>
        <button type="button" className="ghost" onClick={() => zoom(1.2)} title="Phóng to">
          +
        </button>
      </div>
      <div className="doc-scroll" ref={scrollRef}>
        {scale && <PdfViewer doc={doc} scale={scale} {...viewer} />}
      </div>
    </div>
  );
}
