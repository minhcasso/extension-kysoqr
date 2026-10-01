import { useEffect, useRef, useState } from 'react';
import { PDFDateString, type PDFDocumentProxy } from '../lib/pdf';
import { Icon } from './Icon';

interface Info {
  Title?: string;
  Author?: string;
  Subject?: string;
  Keywords?: string;
  CreationDate?: string;
  ModDate?: string;
  Creator?: string;
  Producer?: string;
  PDFFormatVersion?: string;
  IsLinearized?: boolean;
}

interface Props {
  doc: PDFDocumentProxy;
  fileName: string;
  fileSize: number;
  onClose: () => void;
}

/** Khổ giấy phổ biến (mm, dọc), dùng để gọi tên khổ trang. */
const PAPER: [string, number, number][] = [
  ['A3', 297, 420],
  ['A4', 210, 297],
  ['A5', 148, 210],
  ['Letter', 215.9, 279.4],
  ['Legal', 215.9, 355.6],
];

const PT_TO_MM = 25.4 / 72;

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function formatDate(raw: string | undefined) {
  if (!raw) return null;
  const d = PDFDateString.toDateObject(raw);
  return d ? d.toLocaleString('vi-VN') : raw;
}

function pageSizeText(view: number[]) {
  const [x0 = 0, y0 = 0, x1 = 0, y1 = 0] = view;
  const w = Math.abs(x1 - x0) * PT_TO_MM;
  const h = Math.abs(y1 - y0) * PT_TO_MM;
  const short = Math.min(w, h);
  const long = Math.max(w, h);
  const name = PAPER.find(([, a, b]) => Math.abs(a - short) < 2 && Math.abs(b - long) < 2)?.[0];
  const orient = w > h ? 'ngang' : 'dọc';
  return `${w.toFixed(0)} × ${h.toFixed(0)} mm${name ? ` (${name}, ${orient})` : ''}`;
}

/** Hộp thoại "Thuộc tính tài liệu" như trình xem PDF của Chrome. */
export function DocumentProperties({ doc, fileName, fileSize, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [info, setInfo] = useState<Info | null>(null);
  const [pageSize, setPageSize] = useState<string | null>(null);

  useEffect(() => {
    if (ref.current && !ref.current.open) ref.current.showModal();
    let cancelled = false;
    void doc.getMetadata().then(
      (m) => !cancelled && setInfo((m.info ?? {}) as Info),
      () => !cancelled && setInfo({}),
    );
    void doc.getPage(1).then((p) => !cancelled && setPageSize(pageSizeText(p.view)));
    return () => {
      cancelled = true;
    };
  }, [doc]);

  const rows: [string, string | null | undefined][] = [
    ['Tên file', fileName],
    ['Dung lượng', formatSize(fileSize)],
    ['Tiêu đề', info?.Title],
    ['Tác giả', info?.Author],
    ['Chủ đề', info?.Subject],
    ['Từ khoá', info?.Keywords],
    ['Ngày tạo', formatDate(info?.CreationDate)],
    ['Ngày sửa', formatDate(info?.ModDate)],
    ['Ứng dụng tạo', info?.Creator],
    ['Trình tạo PDF', info?.Producer],
    ['Phiên bản PDF', info?.PDFFormatVersion],
    ['Số trang', String(doc.numPages)],
    ['Khổ trang', pageSize],
    ['Xem nhanh trên web', info ? (info.IsLinearized ? 'Có' : 'Không') : null],
  ];

  return (
    <dialog ref={ref} className="doc-props" onClose={onClose} onCancel={onClose}>
      <div className="doc-props-head">
        <h2>Thuộc tính tài liệu</h2>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Đóng">
          <Icon name="x" size={16} />
        </button>
      </div>
      <dl className="doc-props-list">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v?.toString().trim() || '—'}</dd>
          </div>
        ))}
      </dl>
      <div className="doc-props-foot">
        <button type="button" className="btn-outline" onClick={onClose}>
          Đóng
        </button>
      </div>
    </dialog>
  );
}
