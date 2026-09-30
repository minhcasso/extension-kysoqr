import { useEffect, useRef, useState } from 'react';
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

export interface MenuItem {
  label: string;
  icon: Parameters<typeof Icon>[0]['name'];
  onClick: () => void;
}

function OverflowMenu({ items }: { items: MenuItem[] }) {
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
        className="rt-btn"
        aria-label="Thêm"
        title="Thêm"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <circle cx="12" cy="5" r="1.8" />
          <circle cx="12" cy="12" r="1.8" />
          <circle cx="12" cy="19" r="1.8" />
        </svg>
      </button>
      {open && (
        <ul className="rt-menu" role="menu">
          {items.map((it) => (
            <li key={it.label}>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  it.onClick();
                }}
              >
                <Icon name={it.icon} size={16} /> {it.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function ReaderToolbar({
  fileName,
  verify,
  viewer,
  download,
  menu,
  onSign,
  signing,
}: {
  fileName: string | null;
  /** Chỉ có khi PDF có chữ ký số. */
  verify: { count: number; tone: VerifyTone; open: boolean; onToggle: () => void } | null;
  viewer: {
    page: number;
    numPages: number;
    onJump: (page: number) => void;
    scale: number | null;
    onZoom: (factor: number) => void;
    onFit: () => void;
  } | null;
  download: { url: string; name: string } | null;
  menu: MenuItem[];
  onSign: (() => void) | null;
  /** Bảng ký đang mở. */
  signing: boolean;
}) {
  return (
    <header className="rt">
      <div className="rt-left">
        {verify && (
          <button
            type="button"
            className={`rt-btn rt-verify ${verify.open ? 'on' : ''}`}
            onClick={verify.onToggle}
            aria-expanded={verify.open}
            title={verify.open ? 'Ẩn bảng xác minh chữ ký' : 'Xem xác minh chữ ký'}
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
            <span className={`rt-count ${verify.tone}`}>{verify.count}</span>
          </button>
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
          <span className="rt-zoom">{viewer.scale ? Math.round(viewer.scale * 100) : 100}%</span>
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
          <button
            type="button"
            className="rt-btn"
            onClick={viewer.onFit}
            aria-label="Vừa khít chiều ngang"
            title="Vừa khít chiều ngang (Ctrl 0)"
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
              <path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3" />
            </svg>
          </button>
        </div>
      )}

      <div className="rt-right">
        {download && (
          <a
            className="rt-btn"
            href={download.url}
            download={download.name}
            aria-label="Tải xuống"
            title="Tải xuống"
          >
            <Icon name="download" size={18} />
          </a>
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
