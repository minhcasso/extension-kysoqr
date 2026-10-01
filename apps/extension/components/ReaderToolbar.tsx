import { useEffect, useRef, useState, type ReactNode } from 'react';
import { MAX_SCALE, MIN_SCALE, type FitMode } from './DocumentView';
import { Icon } from './Icon';

export type VerifyTone = 'ok' | 'warn' | 'bad' | 'neutral';

function PageNav({
  page,
  numPages,
  onJump,
}: {
  page: number;
  numPages: number;
  onJump: (page: number) => void;
}) {
  const [draft, setDraft] = useState(String(page));
  useEffect(() => setDraft(String(page)), [page]);
  const commit = () => {
    const n = Math.min(numPages, Math.max(1, Number(draft) || page));
    setDraft(String(n));
    if (n !== page) onJump(n);
  };
  return (
    <span className="rt-page">
      <input
        value={draft}
        inputMode="numeric"
        aria-label="Trang hiện tại"
        onChange={(e) => setDraft(e.target.value.replace(/\D/g, ''))}
        onBlur={commit}
        onFocus={(e) => e.target.select()}
        onKeyDown={(e) => e.key === 'Enter' && (e.target as HTMLInputElement).blur()}
      />
      <span>/ {numPages}</span>
    </span>
  );
}

/** Ô % zoom sửa được như Chrome: gõ số rồi Enter. */
function ZoomInput({
  scale,
  onSetScale,
}: {
  scale: number | null;
  onSetScale: (scale: number) => void;
}) {
  const pct = scale ? Math.round(scale * 100) : 100;
  const [draft, setDraft] = useState(`${pct}%`);
  useEffect(() => setDraft(`${pct}%`), [pct]);
  const commit = () => {
    const n = Number(draft.replace(/\D/g, ''));
    const next = n ? Math.min(MAX_SCALE * 100, Math.max(MIN_SCALE * 100, n)) : pct;
    setDraft(`${next}%`);
    if (next !== pct) onSetScale(next / 100);
  };
  return (
    <span className="rt-zoom">
      <input
        value={draft}
        inputMode="numeric"
        aria-label="Tỷ lệ phóng to"
        onChange={(e) => setDraft(e.target.value.replace(/[^\d%]/g, ''))}
        onBlur={commit}
        onFocus={(e) => e.target.select()}
        onKeyDown={(e) => e.key === 'Enter' && (e.target as HTMLInputElement).blur()}
      />
    </span>
  );
}

export interface MenuItem {
  label: string;
  icon: Parameters<typeof Icon>[0]['name'];
  onClick: () => void;
  /** Lựa chọn đang dùng (hiện dấu ✓). */
  checked?: boolean;
  /** Kẻ một đường ngang phía trên mục này (tách nhóm). */
  divider?: boolean;
}

/** Menu thả xuống dùng chung cho nút ☰ (căn trái) và ⋮ (căn phải). */
function DropdownMenu({
  items,
  align,
  label,
  className = '',
  children,
}: {
  items: MenuItem[];
  align: 'left' | 'right';
  label: string;
  className?: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: PointerEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('pointerdown', close);
    window.addEventListener('keydown', esc);
    return () => {
      window.removeEventListener('pointerdown', close);
      window.removeEventListener('keydown', esc);
    };
  }, [open]);
  return (
    <div className="rt-menu-wrap" ref={ref}>
      <button
        type="button"
        className={`rt-btn ${className}`}
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {children}
      </button>
      {open && (
        <ul className={`rt-menu ${align}`} role="menu">
          {items.map((it) => (
            <li key={it.label} className={it.divider ? 'rt-menu-sep' : undefined}>
              <button
                type="button"
                role={it.checked === undefined ? 'menuitem' : 'menuitemradio'}
                aria-checked={it.checked}
                onClick={() => {
                  setOpen(false);
                  it.onClick();
                }}
              >
                <Icon name={it.icon} size={16} /> <span className="rt-menu-label">{it.label}</span>
                {it.checked && <Icon name="check" size={16} className="rt-menu-check" />}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function OverflowMenu({ items }: { items: MenuItem[] }) {
  return (
    <DropdownMenu items={items} align="right" label="Thêm">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
        <circle cx="12" cy="5" r="1.8" />
        <circle cx="12" cy="12" r="1.8" />
        <circle cx="12" cy="19" r="1.8" />
      </svg>
    </DropdownMenu>
  );
}

export function ReaderToolbar({
  fileName,
  sidebar,
  viewer,
  download,
  print,
  menu,
  onSign,
  signing,
}: {
  fileName: string | null;
  /** Nút ☰: menu chọn bảng bên (Thu nhỏ / Xác minh chữ ký / Preview). `count` > 0 khi PDF có chữ ký. */
  sidebar: { items: MenuItem[]; open: boolean; count: number; tone: VerifyTone } | null;
  viewer: {
    page: number;
    numPages: number;
    onJump: (page: number) => void;
    scale: number | null;
    onZoom: (factor: number) => void;
    onSetScale: (scale: number) => void;
    fitMode: FitMode;
    onToggleFit: () => void;
    onRotate: (delta: number) => void;
  } | null;
  download: { bytes: Uint8Array; name: string } | null;
  /** Nút In; `busy` khi đang chuẩn bị các trang để in. */
  print: { onPrint: () => void; busy: boolean } | null;
  menu: MenuItem[];
  onSign: (() => void) | null;
  /** Bảng ký đang mở. */
  signing: boolean;
}) {
  return (
    <header className="rt">
      <div className="rt-left">
        {sidebar && (
          <DropdownMenu
            items={sidebar.items}
            align="left"
            label="Bảng bên"
            className={`rt-verify ${sidebar.open ? 'on' : ''}`}
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M4 6h16M4 12h16M4 18h16" />
            </svg>
            {sidebar.count > 0 && (
              <span className={`rt-count ${sidebar.tone}`}>{sidebar.count}</span>
            )}
          </DropdownMenu>
        )}
        <span className="rt-title" title={fileName ?? undefined}>
          {fileName ?? 'KysoQR'}
        </span>
      </div>

      {viewer && (
        <div className="rt-center">
          <PageNav page={viewer.page} numPages={viewer.numPages} onJump={viewer.onJump} />
          <span className="rt-sep" />
          <button
            type="button"
            className="rt-btn"
            onClick={() => viewer.onZoom(1 / 1.1)}
            aria-label="Thu nhỏ"
            title="Thu nhỏ (Ctrl −)"
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M5 12h14" />
            </svg>
          </button>
          <ZoomInput scale={viewer.scale} onSetScale={viewer.onSetScale} />
          <button
            type="button"
            className="rt-btn"
            onClick={() => viewer.onZoom(1.1)}
            aria-label="Phóng to"
            title="Phóng to (Ctrl +)"
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M5 12h14M12 5v14" />
            </svg>
          </button>
          <span className="rt-sep" />
          {/* Như Chrome: nút cho biết chế độ sẽ chuyển sang khi bấm. */}
          <button
            type="button"
            className="rt-btn"
            onClick={viewer.onToggleFit}
            aria-label={viewer.fitMode === 'width' ? 'Vừa trang' : 'Vừa chiều ngang'}
            title={`${viewer.fitMode === 'width' ? 'Vừa trang' : 'Vừa chiều ngang'} (Ctrl \)`}
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <rect x="3" y="3" width="18" height="18" rx="2" />
              {viewer.fitMode === 'width' ? (
                <path d="M12 7v10m-3-7 3-3 3 3m-6 4 3 3 3-3" />
              ) : (
                <path d="M7 12h10m-7-3-3 3 3 3m4-6 3 3-3 3" />
              )}
            </svg>
          </button>
          <button
            type="button"
            className="rt-btn"
            onClick={() => viewer.onRotate(-90)}
            aria-label="Xoay ngược chiều kim đồng hồ"
            title="Xoay ngược chiều kim đồng hồ (Ctrl [)"
          >
            <Icon name="rotateLeft" size={18} />
          </button>
        </div>
      )}

      <div className="rt-right">
        {download && (
          <a
            className="rt-btn"
            href="#"
            onClick={(e) => {
              e.preventDefault();
              saveFile(download.bytes, download.name);
            }}
            aria-label="Tải xuống"
            title="Tải xuống"
          >
            <Icon name="download" size={18} />
          </a>
        )}
        {print && (
          <button
            type="button"
            className="rt-btn"
            onClick={print.onPrint}
            disabled={print.busy}
            aria-busy={print.busy}
            aria-label="In"
            title={print.busy ? 'Đang chuẩn bị bản in…' : 'In (Ctrl P)'}
          >
            {print.busy ? <span className="rt-spinner" /> : <Icon name="printer" size={18} />}
          </button>
        )}
        <OverflowMenu items={menu} />
        {onSign && (
          <button type="button" className={`rt-sign ${signing ? 'on' : ''}`} onClick={onSign}>
            <Icon name="pen" size={15} /> Ký
          </button>
        )}
      </div>
    </header>
  );
}

/** Chỉ tạo bản sao file (Blob) khi người dùng bấm tải, không giữ sẵn cho mọi tài liệu. */
function saveFile(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([bytes.slice()], { type: 'application/pdf' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
