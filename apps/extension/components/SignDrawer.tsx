import { useEffect, useState, type ReactNode } from 'react';
import logo from '../assets/kysoqr-icon.svg';
import { getHistory, type HistoryItem } from '../lib/storage';
import { Icon } from './Icon';

const STEPS = ['Cấu hình', 'Quét QR', 'Hoàn tất'];

function StepBar({ current }: { current: number }) {
  return (
    <ol className="stepbar" aria-label="Tiến trình ký">
      {STEPS.map((label, i) => (
        <li
          key={label}
          className={i < current ? 'done' : i === current ? 'active' : ''}
          aria-current={i === current ? 'step' : undefined}
        >
          <span className="step-dot">{i < current ? '✓' : i + 1}</span>
          <span className="step-label">{label}</span>
        </li>
      ))}
    </ol>
  );
}

/** Bảng ký trượt ra từ bên phải — nơi duy nhất mang thương hiệu KysoQR. */
export function SignDrawer({
  step,
  title,
  onClose,
  children,
}: {
  /** null: không hiện thanh bước (vd. danh sách yêu cầu gần đây). */
  step: number | null;
  title?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <aside className="drawer" aria-label="Ký số với KysoQR">
      <div className="drawer-head">
        <div className="brand">
          <img src={logo} alt="" width={34} height={34} />
          <span>
            KysoQR<span className="brand-tld">.com</span>
          </span>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Đóng" title="Đóng">
          <Icon name="x" size={18} />
        </button>
      </div>
      {step !== null && <StepBar current={step} />}
      {title && <h2 className="drawer-title">{title}</h2>}
      <div className="drawer-body">{children}</div>
      <p className="drawer-foot">Ký số bằng Cas ID · chứng thư số được CA cấp phép</p>
    </aside>
  );
}

const STATE_LABELS: Record<string, string> = {
  NEW: 'Chờ ký',
  ACCEPTED: 'Đang xử lý',
  COMPLETED: 'Đã ký',
  REJECTED: 'Bị từ chối',
  EXPIRED: 'Hết hạn',
};

export function RecentRequests({ onOpen }: { onOpen: (item: HistoryItem) => void }) {
  const [items, setItems] = useState<HistoryItem[] | null>(null);
  useEffect(() => {
    void getHistory().then(setItems);
  }, []);
  if (!items) return null;
  if (!items.length) return <p className="muted small">Chưa có yêu cầu ký nào trên máy này.</p>;
  return (
    <ul className="requests">
      {items.map((h) => (
        <li key={h.signRequestId}>
          <button type="button" onClick={() => onOpen(h)}>
            <span className="req-name">{h.documentName}</span>
            <span className="muted small">
              {new Date(h.createdAt).toLocaleString('vi-VN')} ·{' '}
              {STATE_LABELS[h.state ?? 'NEW'] ?? h.state}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}
