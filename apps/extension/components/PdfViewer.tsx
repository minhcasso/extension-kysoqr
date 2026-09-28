import {
  ratiosToViewportBox,
  viewportBoxToRatios,
  type FieldRatios,
  type FieldType,
  type PageView as PageBox,
  type Transform,
  type ViewportBox,
} from '@kysoqr/shared';
import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import type { PDFDocumentProxy, PDFPageProxy, PageViewport } from '../lib/pdf';

export interface Field {
  id: string;
  page: number;
  fieldType: FieldType;
  ratios: FieldRatios;
}

export const FIELD_LABELS: Record<FieldType, string> = {
  SIGNATURE: 'Chữ ký',
  INITIAL: 'Ký nháy',
  STAMP: 'Con dấu',
};

/** Kích thước mặc định của ô ký mới, đơn vị điểm PDF (1/72 inch). */
const DEFAULT_BOX = { width: 170, height: 60 };
const MIN_BOX_PX = 24;

interface Props {
  doc: PDFDocumentProxy;
  scale: number;
  fields?: Field[];
  onFieldsChange?: (fields: Field[]) => void;
  placing?: FieldType | null;
  onPlaced?: (field: Field) => void;
  selectedId?: string | null;
  onSelect?: (id: string | null) => void;
}

export function PdfViewer(props: Props) {
  const pages = Array.from({ length: props.doc.numPages }, (_, i) => i + 1);
  return (
    <div className="pages">
      {pages.map((n) => (
        <PageView key={n} pageNumber={n} {...props} />
      ))}
    </div>
  );
}

function PageView({
  doc,
  pageNumber,
  scale,
  fields = [],
  onFieldsChange,
  placing,
  onPlaced,
  selectedId,
  onSelect,
}: Props & { pageNumber: number }) {
  const [page, setPage] = useState<PDFPageProxy | null>(null);
  const [visible, setVisible] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    let cancelled = false;
    void doc.getPage(pageNumber).then((p) => !cancelled && setPage(p));
    return () => {
      cancelled = true;
    };
  }, [doc, pageNumber]);

  // Chỉ vẽ trang khi gần vào vùng nhìn thấy (tài liệu nhiều trang vẫn mượt).
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const io = new IntersectionObserver(([e]) => e?.isIntersecting && setVisible(true), {
      rootMargin: '800px 0px',
    });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const viewport = page?.getViewport({ scale });

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
    });
    task.promise.catch(() => {
      // bị huỷ do đổi zoom
    });
    return () => task.cancel();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, scale, visible]);

  const size = viewport
    ? { width: viewport.width, height: viewport.height }
    : { width: 595 * scale, height: 842 * scale };
  const pageFields = fields.filter((f) => f.page === pageNumber);
  const editable = Boolean(onFieldsChange);

  function handlePlace(e: ReactPointerEvent<HTMLDivElement>) {
    if (!placing || !viewport || !page || (e.target as HTMLElement).closest('.field')) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const w = Math.min(DEFAULT_BOX.width * scale, viewport.width);
    const h = Math.min(DEFAULT_BOX.height * scale, viewport.height);
    const box = {
      left: clamp(e.clientX - rect.left - w / 2, 0, viewport.width - w),
      top: clamp(e.clientY - rect.top - h / 2, 0, viewport.height - h),
      width: w,
      height: h,
    };
    onPlaced?.({
      id: crypto.randomUUID(),
      page: pageNumber,
      fieldType: placing,
      ratios: viewportBoxToRatios(box, viewport.transform as unknown as Transform, page.view as unknown as PageBox),
    });
  }

  return (
    <div className="page-wrap">
      <div
        ref={wrapRef}
        className={`page ${placing ? 'placing' : ''}`}
        style={size}
        onPointerDown={editable ? handlePlace : undefined}
      >
        <canvas ref={canvasRef} style={size} />
        {page &&
          viewport &&
          pageFields.map((f) => (
            <FieldBox
              key={f.id}
              field={f}
              page={page}
              viewport={viewport}
              editable={editable}
              selected={f.id === selectedId}
              onSelect={() => onSelect?.(f.id)}
              onChange={(ratios) =>
                onFieldsChange?.(fields.map((x) => (x.id === f.id ? { ...x, ratios } : x)))
              }
              onRemove={() => onFieldsChange?.(fields.filter((x) => x.id !== f.id))}
            />
          ))}
      </div>
      <div className="page-number">Trang {pageNumber}</div>
    </div>
  );
}

const clamp = (v: number, min: number, max: number) => Math.min(Math.max(v, min), Math.max(min, max));

function FieldBox({
  field,
  page,
  viewport,
  editable,
  selected,
  onSelect,
  onChange,
  onRemove,
}: {
  field: Field;
  page: PDFPageProxy;
  viewport: PageViewport;
  editable: boolean;
  selected: boolean;
  onSelect: () => void;
  onChange: (ratios: FieldRatios) => void;
  onRemove: () => void;
}) {
  const transform = viewport.transform as unknown as Transform;
  const view = page.view as unknown as PageBox;
  const [draft, setDraft] = useState<ViewportBox | null>(null);
  const box = draft ?? ratiosToViewportBox(field.ratios, transform, view);

  function startGesture(e: ReactPointerEvent, mode: 'move' | 'resize') {
    if (!editable) return;
    e.stopPropagation();
    e.preventDefault();
    onSelect();
    const start = { x: e.clientX, y: e.clientY, box };
    let latest = box;
    const onMove = (ev: PointerEvent) => {
      const dx = ev.clientX - start.x;
      const dy = ev.clientY - start.y;
      latest =
        mode === 'move'
          ? {
              ...start.box,
              left: clamp(start.box.left + dx, 0, viewport.width - start.box.width),
              top: clamp(start.box.top + dy, 0, viewport.height - start.box.height),
            }
          : {
              ...start.box,
              width: clamp(start.box.width + dx, MIN_BOX_PX, viewport.width - start.box.left),
              height: clamp(start.box.height + dy, MIN_BOX_PX, viewport.height - start.box.top),
            };
      setDraft(latest);
    };
    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      setDraft(null);
      if (latest !== box) onChange(viewportBoxToRatios(latest, transform, view));
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  }

  return (
    <div
      className={`field ${field.fieldType.toLowerCase()} ${selected ? 'selected' : ''} ${editable ? 'editable' : ''}`}
      style={box}
      onPointerDown={(e) => startGesture(e, 'move')}
    >
      <span className="field-label">{FIELD_LABELS[field.fieldType]}</span>
      {editable && (
        <>
          <button
            type="button"
            className="field-remove"
            title="Xoá ô ký"
            onPointerDown={(e) => e.stopPropagation()}
            onClick={onRemove}
          >
            ×
          </button>
          <span className="field-resize" onPointerDown={(e) => startGesture(e, 'resize')} />
        </>
      )}
    </div>
  );
}
