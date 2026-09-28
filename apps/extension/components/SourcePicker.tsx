import { useEffect, useState, type DragEvent } from 'react';
import type { SourceError } from '../lib/source';
import { getHistory, type HistoryItem } from '../lib/storage';

const STATE_LABELS: Record<string, string> = {
  NEW: 'Chờ ký',
  ACCEPTED: 'Đang xử lý',
  COMPLETED: 'Đã ký',
  REJECTED: 'Bị từ chối',
  EXPIRED: 'Hết hạn',
};

/** Màn hình khi không tự lấy được PDF: giải thích lỗi, cho chọn file, xem lịch sử. */
export function SourcePicker({
  error,
  onFile,
  onGrantPermission,
  onOpenHistory,
}: {
  error?: SourceError | Error | null;
  onFile: (file: File) => void;
  onGrantPermission: (origin: string) => void;
  onOpenHistory: (item: HistoryItem) => void;
}) {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    void getHistory().then(setHistory);
  }, []);

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) onFile(file);
  }

  const kind = error && 'kind' in error ? error.kind : undefined;
  const origin = error && 'origin' in error ? error.origin : undefined;

  return (
    <div className="center-card wide">
      <div className="title-row">
        <h1>KysoQR – Ký số PDF</h1>
        <button type="button" className="ghost header-link" onClick={() => void browser.runtime.openOptionsPage()}>
          Cài đặt
        </button>
      </div>

      {error && (
        <div className="error">
          <p>{error.message}</p>
          {kind === 'file-access' && (
            <>
              <p>
                Để ký file trên máy, bật <b>“Cho phép truy cập vào URL của tệp”</b> (Allow access to file URLs) cho
                KysoQR, rồi tải lại trang này.
              </p>
              <button
                type="button"
                className="secondary"
                onClick={() => browser.tabs.create({ url: `chrome://extensions/?id=${browser.runtime.id}` })}
              >
                Mở cài đặt extension
              </button>
            </>
          )}
          {kind === 'permission' && origin && (
            <button type="button" className="primary" onClick={() => onGrantPermission(origin)}>
              Cấp quyền và tải lại
            </button>
          )}
        </div>
      )}

      <label
        className={`dropzone ${dragging ? 'dragging' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <input
          type="file"
          accept="application/pdf,.pdf"
          hidden
          onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])}
        />
        <strong>Kéo thả file PDF vào đây</strong>
        <span>hoặc bấm để chọn file (tối đa 10MB)</span>
      </label>

      {history.length > 0 && (
        <>
          <h3>Yêu cầu ký gần đây</h3>
          <ul className="history">
            {history.map((h) => (
              <li key={h.signRequestId}>
                <button type="button" className="ghost" onClick={() => onOpenHistory(h)}>
                  <span>{h.documentName}</span>
                  <span className="muted small">
                    {new Date(h.createdAt).toLocaleString('vi-VN')} · {STATE_LABELS[h.state ?? 'NEW'] ?? h.state}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
