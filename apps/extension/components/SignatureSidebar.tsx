import type { ChainCertificate, RevocationResult } from '@kysoqr/shared';
import {
  verdict,
  type SignatureCheck,
  type SignaturesState,
  type Verdict,
} from '../lib/useSignatures';
import { certInfoFromDer, type CertInfo, type Integrity } from '../lib/verify';
import { Icon, type IconName } from './Icon';

const fmt = (d: Date | string | null | undefined) =>
  d ? new Date(d).toLocaleString('vi-VN') : '—';

export const VERDICTS: Record<Verdict, { label: string; icon: IconName; tone: string }> = {
  checking: { label: 'Đang kiểm tra', icon: 'refresh', tone: 'neutral' },
  valid: { label: 'Hợp lệ', icon: 'checkCircle', tone: 'ok' },
  untrusted: { label: 'Chưa xác minh gốc', icon: 'alert', tone: 'warn' },
  modified: { label: 'Bị sửa sau khi ký', icon: 'triangle', tone: 'bad' },
  revoked: { label: 'Đã thu hồi', icon: 'triangle', tone: 'bad' },
  invalid: { label: 'Không hợp lệ', icon: 'triangle', tone: 'bad' },
};

const INTEGRITY: Record<Integrity, string> = {
  intact: 'Nội dung PDF khớp với bản đã ký',
  'later-revision': 'Khớp với bản đã ký; sau đó tài liệu được ký hoặc bổ sung thêm',
  modified: 'Tài liệu có nội dung được thêm hoặc sửa sau khi ký',
};

const REVOCATION: Record<RevocationResult['status'], string> = {
  good: 'Chứng thư số chưa bị thu hồi',
  revoked: 'Chứng thư số ĐÃ BỊ THU HỒI',
  unknown: 'Máy chủ không nhận ra chứng thư này',
  error: 'Không kiểm tra được',
  unsupported: 'Chưa hỗ trợ kiểm tra',
  none: 'Không khai báo (thường gặp ở chứng thư gốc)',
};

function Revocation({
  label,
  result,
  fallbackUrl,
  failed,
}: {
  label: string;
  result?: RevocationResult;
  fallbackUrl: string | null;
  failed?: boolean;
}) {
  const url = result?.url ?? fallbackUrl;
  const text = result ? REVOCATION[result.status] : failed ? REVOCATION.error : 'Đang kiểm tra…';
  const tone =
    result?.status === 'good' ? 'ok-text' : result?.status === 'revoked' ? 'error-text' : '';
  return (
    <div>
      <span className="k">{label}: </span>
      <span className={tone}>
        {text}
        {result?.revokedAt && ` lúc ${fmt(result.revokedAt)}`}
      </span>
      {result?.detail && result.status !== 'good' && (
        <span className="muted"> ({result.detail})</span>
      )}
      {result?.detail && result.status === 'good' && (
        <span className="muted"> · {result.detail}</span>
      )}
      {url && <div className="url">[{url}]</div>}
    </div>
  );
}

function certTitle(cert: CertInfo, index: number, isRoot: boolean) {
  if (index === 0) return 'Chứng thư số người ký';
  if (isRoot) return 'Chứng thư gốc (Root CA)';
  return 'Tổ chức phát hành (CA)';
}

const SOURCE_NOTE: Record<ChainCertificate['source'], string | null> = {
  document: null,
  'trust-store': 'Lấy từ danh sách chứng thư gốc tin cậy',
  aia: 'Tải từ địa chỉ của tổ chức phát hành',
};

function CertCard({
  cert,
  index,
  checked,
  failed,
}: {
  cert: CertInfo;
  index: number;
  checked?: ChainCertificate;
  failed?: boolean;
}) {
  const isRoot = cert.subject === cert.issuer && cert.isCa;
  return (
    <div className="cert-card">
      <div className="cert-head">
        <span>{certTitle(cert, index, isRoot)}</span>
        <span className="chip">#{index}</span>
      </div>
      <div className="kv">
        <div>
          <span className="k">Chủ thể: </span>
          {cert.subject}
        </div>
        <div>
          <span className="k">Tổ chức phát hành: </span>
          {cert.issuer}
        </div>
        <div>
          <span className="k">Số seri: </span>
          <span className="mono">{cert.serialNumber}</span>
        </div>
        <div>
          <span className="k">Hiệu lực: </span>
          {fmt(cert.validFrom)} – {fmt(cert.validTo)}
        </div>
        {checked?.signatureValid === false && (
          <div className="error-text">Chữ ký của chứng thư này không hợp lệ</div>
        )}
        {checked && SOURCE_NOTE[checked.source] && (
          <div className="muted">{SOURCE_NOTE[checked.source]}</div>
        )}
        <Revocation
          label="OCSP"
          result={checked?.ocsp}
          fallbackUrl={cert.ocspUrl}
          failed={failed}
        />
        <Revocation label="CRL" result={checked?.crl} fallbackUrl={cert.crlUrl} failed={failed} />
      </div>
    </div>
  );
}

function ChainDetail({ item }: { item: SignatureCheck }) {
  const { chain, signature } = item;
  if (chain.kind !== 'done') {
    return (
      <>
        {signature.certificates.map((c, i) => (
          <CertCard key={c.serialNumber + i} cert={c} index={i} failed={chain.kind === 'error'} />
        ))}
        {chain.kind === 'error' && (
          <div className="note warn">Không kiểm tra được chuỗi chứng thư: {chain.message}</div>
        )}
      </>
    );
  }
  const r = chain.result;
  return (
    <>
      {r.chain.map((c, i) => (
        <CertCard key={c.der.slice(-24) + i} cert={certInfoFromDer(c.der)} index={i} checked={c} />
      ))}
      {!r.trusted && (
        <div className="note warn">
          {r.trustStoreConfigured
            ? 'Chứng thư gốc không nằm trong danh sách tin cậy.'
            : 'Máy chủ KysoQR chưa cấu hình danh sách chứng thư gốc tin cậy, nên chưa xác minh được tới gốc.'}
        </div>
      )}
      {r.chainError && <div className="note warn">{r.chainError}</div>}
    </>
  );
}

function SignatureCard({ item }: { item: SignatureCheck }) {
  const s = item.signature;
  const v = VERDICTS[verdict(item)];
  const hasDetails = s.certificates.length > 0 || s.reason || s.location || s.hasTimestamp;
  return (
    <article className="sig-card">
      <header className="sig-head">
        <span className="sig-title">
          {s.kind === 'document-timestamp' ? 'Dấu thời gian' : 'Chữ ký số'} #{s.index}
        </span>
        <span className={`badge ${v.tone}`}>
          <Icon name={v.icon} size={12} /> {v.label}
        </span>
      </header>
      <div className="kv">
        <div>
          <span className="k">Người ký: </span>
          {s.signerName ?? '—'}
        </div>
        <div>
          <span className="k">Thời điểm ký: </span>
          {fmt(s.signedAt)}
        </div>
        <div>
          <span className="k">Tài liệu đã ký: </span>
          {s.signatureValid ? (
            INTEGRITY[s.integrity]
          ) : (
            <span className="error-text">{s.error}</span>
          )}
        </div>
      </div>
      {hasDetails && (
        <details className="chain">
          <summary>
            Xem chi tiết <Icon name="chevronDown" size={12} />
          </summary>
          {(s.reason || s.location || s.hasTimestamp) && (
            <div className="kv">
              {s.reason && (
                <div>
                  <span className="k">Lý do: </span>
                  {s.reason}
                </div>
              )}
              {s.location && (
                <div>
                  <span className="k">Nơi ký: </span>
                  {s.location}
                </div>
              )}
              {s.hasTimestamp && (
                <div>
                  <span className="k">Dấu thời gian: </span>
                  Có (thời điểm ký do máy chủ dấu thời gian xác nhận)
                </div>
              )}
            </div>
          )}
          {s.certificates.length > 0 && (
            <>
              <div className="chain-title">Chuỗi chứng thư số</div>
              <ChainDetail item={item} />
            </>
          )}
        </details>
      )}
    </article>
  );
}

/** Bảng xác minh bên trái — chỉ hiện khi PDF có chữ ký số. */
export function SignatureSidebar({
  signatures,
  onClose,
}: {
  signatures: SignaturesState;
  onClose: () => void;
}) {
  const count = signatures.items.length;
  return (
    <aside className="sidebar" aria-label="Xác minh chữ ký">
      <div className="sidebar-head">
        <div>
          <h2>Xác minh chữ ký</h2>
          <p className="muted small">Tài liệu này có {count} chữ ký số.</p>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Ẩn bảng xác minh">
          <Icon name="x" size={16} />
        </button>
      </div>
      <div className="sidebar-body">
        {signatures.items.map((item) => (
          <SignatureCard key={item.signature.index} item={item} />
        ))}
      </div>
    </aside>
  );
}
