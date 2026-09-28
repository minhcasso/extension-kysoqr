import type { SignRequestStatusResponse } from '@kysoqr/shared';
import { toDataURL } from 'qrcode';
import { useEffect, useState } from 'react';
import { getSignedFile, getStatus } from '../lib/api';
import { updateHistoryState, type HistoryItem } from '../lib/storage';

const FAST_POLL_MS = 2_000;
const SLOW_POLL_MS = 5_000;
const FAST_PHASE_MS = 60_000;

export function SigningStatus({
  item,
  onDone,
  onRestart,
}: {
  item: HistoryItem;
  onDone: (signed: Uint8Array, status: SignRequestStatusResponse) => void;
  onRestart: () => void;
}) {
  const [qr, setQr] = useState<string | null>(null);
  const [status, setStatus] = useState<SignRequestStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!item.qrContent) return;
    toDataURL(item.qrContent, { width: 260, margin: 1 }).then(setQr, () => setQr(null));
  }, [item.qrContent]);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  // Theo dõi trạng thái ngay trong trang (service worker MV3 có thể bị tắt giữa chừng).
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const startedAt = Date.now();

    async function tick() {
      try {
        const s = await getStatus(item.signRequestId, item.accessToken);
        if (stopped) return;
        setStatus(s);
        setError(null);
        void updateHistoryState(item.signRequestId, s.expired ? 'EXPIRED' : s.state);
        if (s.state === 'COMPLETED' && s.fileReady) {
          const signed = await getSignedFile(item.signRequestId, item.accessToken);
          if (!stopped) onDone(signed, s);
          return;
        }
        if (s.state === 'REJECTED' || s.expired) return;
      } catch (e) {
        if (stopped) return;
        setError(e instanceof Error ? e.message : String(e));
      }
      const delay = Date.now() - startedAt < FAST_PHASE_MS ? FAST_POLL_MS : SLOW_POLL_MS;
      timer = setTimeout(tick, delay);
    }
    void tick();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item.signRequestId]);

  const remainingMs = Date.parse(item.expiresAt) - now;
  const state = status?.expired || (remainingMs <= 0 && status?.state === 'NEW') ? 'EXPIRED' : (status?.state ?? item.state ?? 'NEW');

  return (
    <div className="center-card">
      <h2>{item.documentName}</h2>
      {(state === 'NEW' || state === 'ACCEPTED' || state === 'COMPLETED') && <Steps state={state} />}

      {state === 'NEW' && (
        <>
          <p className="lead">
            {item.pushSent
              ? `Đã gửi yêu cầu tới app Cas ID trên điện thoại của bạn. Mở thông báo để ký${item.qrContent ? ', hoặc quét mã QR bên dưới' : ''}.`
              : 'Mở app Cas ID trên điện thoại và quét mã QR để ký.'}
          </p>
          {qr ? (
            <img className="qr" src={qr} alt="Mã QR ký số Cas ID" width={260} height={260} />
          ) : (
            !item.qrContent && <p className="muted small">Cas ID không trả về mã QR cho yêu cầu này.</p>
          )}
          <p className="muted">Mã hết hạn sau {formatRemaining(remainingMs)}</p>
        </>
      )}

      {state === 'ACCEPTED' && (
        <>
          <div className="spinner" />
          <p className="lead">Bạn đã xác nhận trên Cas ID. Hệ thống đang đóng chữ ký số vào tài liệu…</p>
        </>
      )}

      {state === 'COMPLETED' && (
        <>
          <div className="spinner" />
          <p className="lead">Ký thành công. Đang tải file đã ký…</p>
        </>
      )}

      {state === 'REJECTED' && (
        <>
          <p className="lead error-text">Yêu cầu ký đã bị từ chối trên app Cas ID.</p>
          <button type="button" className="primary" onClick={onRestart}>
            Tạo yêu cầu mới
          </button>
        </>
      )}

      {state === 'EXPIRED' && (
        <>
          <p className="lead error-text">Yêu cầu ký đã hết hạn (quá 30 phút).</p>
          <button type="button" className="primary" onClick={onRestart}>
            Tạo yêu cầu mới
          </button>
        </>
      )}

      {(state === 'ACCEPTED' || state === 'COMPLETED') && (
        <p className="muted small">
          Bạn có thể đóng tab này. File đã ký vẫn được lưu và mở lại được ở “Yêu cầu ký gần đây”.
        </p>
      )}
      {error && <div className="error">{error} Đang thử lại…</div>}
      <p className="muted small">Mã yêu cầu: {item.signRequestId}</p>
    </div>
  );
}

const STEPS = [
  { key: 'sent', label: 'Gửi yêu cầu ký' },
  { key: 'NEW', label: 'Xác nhận trên app Cas ID' },
  { key: 'ACCEPTED', label: 'Đóng chữ ký số vào tài liệu' },
  { key: 'COMPLETED', label: 'Tải file đã ký về trình duyệt' },
] as const;

function Steps({ state }: { state: 'NEW' | 'ACCEPTED' | 'COMPLETED' }) {
  const active = STEPS.findIndex((s) => s.key === state);
  return (
    <ol className="steps">
      {STEPS.map((s, i) => (
        <li key={s.key} className={i < active ? 'done' : i === active ? 'active' : ''}>
          <span className="dot">{i < active ? '✓' : i + 1}</span>
          {s.label}
        </li>
      ))}
    </ol>
  );
}

function formatRemaining(ms: number) {
  if (ms <= 0) return '0:00';
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
