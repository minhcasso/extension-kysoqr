import type { ChainCertInfo, RevocationCheckResult, VerificationStatus } from '@kysoqr/shared';
import {
  commonName,
  verdict,
  type SignatureCheck,
  type SignaturesState,
  type Verdict,
} from '../lib/useSignatures';
import type { PDFDocumentProxy } from '../lib/pdf';
import { Icon, type IconName } from './Icon';
import { PageThumbnails } from './PageThumbnails';

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

/** Giải thích từng kết quả xác minh của máy chủ (Xsign/kysoqr trả về tiếng Anh). */
const STATUS_TEXT: Record<VerificationStatus, string> = {
  SIGNED_VALID: 'Chữ ký, nội dung và chuỗi chứng thư đều hợp lệ',
  CONTENT_DIGEST_MISMATCH: 'Tài liệu có nội dung được thêm hoặc sửa sau khi ký',
  CHAIN_VALIDATION_FAILED: 'Chuỗi chứng thư số không hợp lệ',
  ROOT_NOT_TRUSTED: 'Chứng thư gốc không nằm trong danh sách Root CA tin cậy',
  SIGNATURE_INVALID: 'Chữ ký không khớp với nội dung tài liệu',
  TRUST_STORE_NOT_CONFIGURED: 'Máy chủ chưa có danh sách Root CA tin cậy',
  UNSUPPORTED_SUBFILTER: 'Chưa hỗ trợ kiểm tra loại chữ ký này',
  UNSUPPORTED_ALGORITHM: 'Chưa hỗ trợ thuật toán của chữ ký này',
};

const REVOCATION: Record<RevocationCheckResult['status'], string> = {
  not_revoked: 'Chứng thư số chưa bị thu hồi',
  revoked: 'Chứng thư số ĐÃ BỊ THU HỒI',
  unavailable: 'Không kiểm tra được',
};

function Revocation({ label, result }: { label: string; result: RevocationCheckResult | null }) {
  const text = result
    ? result.url || result.status !== 'unavailable'
      ? REVOCATION[result.status]
      : 'Không khai báo'
    : 'Không áp dụng (chứng thư gốc)';
  const tone =
    result?.status === 'not_revoked'
      ? 'ok-text'
      : result?.status === 'revoked'
        ? 'error-text'
        : '';
  return (
    <div>
      <span className="k">{label}: </span>
      <span className={tone}>{text}</span>
      {result?.url && <div className="url">[{result.url}]</div>}
    </div>
  );
}

function certTitle(index: number, isRoot: boolean) {
  if (index === 0) return 'Chứng thư số người ký';
  if (isRoot) return 'Chứng thư gốc (Root CA)';
  return 'Tổ chức phát hành (CA)';
}

function CertCard({ cert, isRoot }: { cert: ChainCertInfo; isRoot: boolean }) {
  return (
    <div className="cert-card">
      <div className="cert-head">
        <span>{certTitle(cert.index, isRoot)}</span>
        <span className="chip">#{cert.index}</span>
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
        <Revocation label="OCSP" result={cert.ocsp} />
        <Revocation label="CRL" result={cert.crl} />
      </div>
    </div>
  );
}

function SignatureCard({ item }: { item: SignatureCheck }) {
  const r = item.result;
  const v = VERDICTS[verdict(item)];
  const chain = r?.certificateChain ?? [];
  return (
    <article className="sig-card">
      <header className="sig-head">
        <span className="sig-title">Chữ ký số #{item.index}</span>
        <span className={`badge ${v.tone}`}>
          <Icon name={v.icon} size={12} /> {v.label}
        </span>
      </header>
      <div className="kv">
        <div>
          <span className="k">Người ký: </span>
          {commonName(r?.certificate?.subject) ?? '—'}
        </div>
        <div>
          <span className="k">Thời điểm ký: </span>
          {fmt(r?.signedAt)}
        </div>
        <div>
          <span className="k">Kết quả: </span>
          {r ? (
            <span className={r.status === 'SIGNED_VALID' ? '' : 'error-text'}>
              {STATUS_TEXT[r.status]}
            </span>
          ) : item.error ? (
            <span className="error-text">{item.error}</span>
          ) : (
            'Đang kiểm tra…'
          )}
        </div>
        {r?.certificateExpiredNow && (
          <div className="muted">
            Chứng thư số đã hết hạn tính tới hôm nay, nhưng còn hiệu lực lúc ký nên chữ ký vẫn có
            giá trị.
          </div>
        )}
      </div>
      {chain.length > 0 && (
        <details className="chain">
          <summary>
            Xem chi tiết <Icon name="chevronDown" size={12} />
          </summary>
          <div className="chain-title">Chuỗi chứng thư số</div>
          {chain.map((c, i) => (
            <CertCard key={c.serialNumber + i} cert={c} isRoot={i === chain.length - 1 && c.isCa} />
          ))}
          {r?.certificateChainRootNotInTrustStore && (
            <div className="note warn">Chứng thư gốc không nằm trong danh sách tin cậy.</div>
          )}
        </details>
      )}
    </article>
  );
}

export type SidebarPanel = 'verify' | 'pages';

/** Bảng bên trái: xác minh chữ ký (mặc định khi PDF có chữ ký) hoặc Preview ảnh thu nhỏ các trang. */
export function SignatureSidebar({
  panel,
  signatures,
  doc,
  page,
  onJump,
  rotation,
  annotations,
  onClose,
}: {
  panel: SidebarPanel;
  signatures: SignaturesState;
  doc: PDFDocumentProxy;
  page: number;
  onJump: (page: number) => void;
  rotation?: number;
  annotations?: boolean;
  onClose: () => void;
}) {
  const count = signatures.items.length;
  const verify = panel === 'verify';
  return (
    <aside className="sidebar" aria-label={verify ? 'Xác minh chữ ký' : 'Preview các trang'}>
      <div className="sidebar-head">
        <div>
          <h2>{verify ? 'Xác minh chữ ký' : 'Preview'}</h2>
          <p className="muted small">
            {verify ? `Tài liệu này có ${count} chữ ký số.` : `${doc.numPages} trang`}
          </p>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Thu nhỏ bảng bên">
          <Icon name="x" size={16} />
        </button>
      </div>
      {verify ? (
        <div className="sidebar-body">
          {signatures.items.map((item) => (
            <SignatureCard key={item.index} item={item} />
          ))}
        </div>
      ) : (
        <PageThumbnails
          doc={doc}
          page={page}
          onJump={onJump}
          rotation={rotation}
          annotations={annotations}
        />
      )}
    </aside>
  );
}
