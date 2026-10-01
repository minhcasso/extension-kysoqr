import type { SignRequestStatusResponse } from '@kysoqr/shared';
import { useEffect, useState } from 'react';
import { getSignedFile, getStatus } from '../lib/api';
import type { SignRequestItem } from '../lib/storage';

const FAST_POLL_MS = 2_000;
const SLOW_POLL_MS = 5_000;
const FAST_PHASE_MS = 60_000;

/** LINK_EXPIRED: đã ký xong nhưng CAS không còn cho tải file (quá hạn hoặc hết 5 lần tải). */
type ViewState = SignRequestStatusResponse['state'] | 'EXPIRED' | 'LINK_EXPIRED';

const isPast = (at: string | undefined | null) => Boolean(at && Date.parse(at) < Date.now());

export function SigningStatus({
  item,
  onDone,
  onRestart,
}: {
  item: SignRequestItem;
  onDone: (signed: Uint8Array, orgIdSigned: string | null) => void;
  onRestart: () => void;
}) {
  const [qr, setQr] = useState<string | null>(null);
  const [status, setStatus] = useState<ViewState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!item.qrContent) return;
    // Nạp thư viện QR chỉ khi cần hiện mã.
    import('qrcode')
      .then(({ toDataURL }) => toDataURL(item.qrContent, { width: 260, margin: 1 }))
      .then(setQr, () => setQr(null));
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

    /** Tải file đúng một lần rồi giao cho trang (bản đã ký nằm trong bộ nhớ để xem / ký tiếp). */
    async function download(identityKey: string, orgIdSigned: string | null) {
      setStatus('COMPLETED');
      try {
        const signed = await getSignedFile(identityKey);
        if (!stopped) onDone(signed, orgIdSigned);
      } catch {
        if (!stopped) setStatus('LINK_EXPIRED');
      }
    }

    async function tick() {
      try {
        const s = await getStatus(item.signRequestId);
        if (stopped) return;
        setError(null);
        const expired = s.state === 'NEW' && isPast(item.expiresAt);
        setStatus(expired ? 'EXPIRED' : s.state);
        if (s.state === 'COMPLETED' && s.identityKey) {
          return void download(s.identityKey, s.orgIdSigned);
        }
        if (s.state === 'REJECTED' || expired) return;
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
  const state: ViewState =
    status === 'NEW' || (!status && (item.state ?? 'NEW') === 'NEW')
      ? remainingMs <= 0
        ? 'EXPIRED'
        : 'NEW'
      : (status ?? (item.state as ViewState));

  const done = state === 'REJECTED' || state === 'EXPIRED' || state === 'LINK_EXPIRED';

  return (
    <>
      <section className="card status-card">
        <span className="eyebrow">Yêu cầu ký</span>
        <h2 className="status-title">{item.documentName}</h2>
        {(state === 'NEW' || state === 'ACCEPTED' || state === 'COMPLETED') && (
          <Steps state={state} />
        )}

        {state === 'NEW' && (
          <>
            <p className="lead">
              {item.pushSent
                ? `Đã gửi yêu cầu tới app Cas ID trên điện thoại. Mở thông báo để ký${item.qrContent ? ', hoặc quét mã QR bên dưới' : ''}.`
                : 'Mở app Cas ID trên điện thoại và quét mã QR để ký.'}
            </p>
            {qr ? (
              <img className="qr" src={qr} alt="Mã QR ký số Cas ID" width={220} height={220} />
            ) : (
              !item.qrContent && (
                <p className="muted small">Cas ID không trả về mã QR cho yêu cầu này.</p>
              )
            )}
            <p className="countdown">
              Mã hết hạn sau <strong>{formatRemaining(remainingMs)}</strong>
            </p>
          </>
        )}

        {state === 'ACCEPTED' && (
          <>
            <div className="spinner" />
            <p className="lead">
              Bạn đã xác nhận trên Cas ID. Hệ thống đang đóng chữ ký số vào tài liệu…
            </p>
          </>
        )}

        {state === 'COMPLETED' && (
          <>
            <div className="spinner" />
            <p className="lead">Ký thành công. Đang tải file đã ký…</p>
          </>
        )}

        {state === 'REJECTED' && (
          <p className="lead error-text">Yêu cầu ký đã bị từ chối trên app Cas ID.</p>
        )}
        {state === 'EXPIRED' && (
          <p className="lead error-text">Yêu cầu ký đã hết hạn (quá 30 phút).</p>
        )}
        {state === 'LINK_EXPIRED' && (
          <p className="lead error-text">
            Tài liệu đã được ký, nhưng không tải được file đã ký từ Cas ID. Vui lòng thử ký lại.
          </p>
        )}

        {(state === 'ACCEPTED' || state === 'COMPLETED') && (
          <p className="muted small">
            Giữ tab này mở cho tới khi tải xong file đã ký.
          </p>
        )}
        {error && <div className="error">{error} Đang thử lại…</div>}
        <p className="muted small mono-id">Mã yêu cầu: {item.signRequestId}</p>
      </section>

      <button
        type="button"
        className={done ? 'sign-btn' : 'btn-outline wide'}
        onClick={onRestart}
      >
        {done
          ? 'Tạo yêu cầu mới'
          : 'Huỷ, quay lại chỉnh vị trí ký'}
      </button>
    </>
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
