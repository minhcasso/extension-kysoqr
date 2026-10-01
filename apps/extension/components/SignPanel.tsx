import { CreateSignRequestMeta, MAX_PDF_BYTES, type SignerKind } from '@kysoqr/shared';
import { useEffect, useMemo, useState, type DragEvent } from 'react';
import { createSignRequest } from '../lib/api';
import type { PdfSource, SourceError } from '../lib/source';
import { getSavedCccd, setSavedCccd, type SignRequestItem } from '../lib/storage';
import { Icon } from './Icon';
import { FIELD_ICONS, FIELD_LABELS, fieldNumber, type Field } from './PdfViewer';

function defaultDocumentName(fileName: string) {
  const base = fileName.replace(/\.pdf$/i, '').trim();
  return base.length >= 10 ? base.slice(0, 240) : `Tài liệu ký số - ${base || 'KysoQR'}`;
}

/** Ô mở file khi chưa có PDF: bấm để chọn hoặc kéo thả. */
export function UploadCard({ onFile }: { onFile: (file: File) => void }) {
  const [dragging, setDragging] = useState(false);
  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) onFile(file);
  }
  return (
    <label
      className={`upload-card ${dragging ? 'dragging' : ''}`}
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
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file) onFile(file);
        }}
      />
      <Icon name="fileCheck" size={44} className="upload-icon" />
      <strong className="upload-title">Mở file PDF</strong>
      <span className="upload-sub">Kéo thả file vào đây, hoặc</span>
      <span className="btn-primary pill upload-btn">Chọn file</span>
      <span className="upload-note">
        Chỉ PDF • tối đa {Math.round(MAX_PDF_BYTES / 1024 / 1024)} MB
      </span>
    </label>
  );
}

/** Lỗi khi tự lấy file PDF của tab (thiếu quyền, file trên máy...) kèm cách khắc phục. */
export function SourceErrorBox({
  error,
  onGrantPermission,
}: {
  error: SourceError | Error;
  onGrantPermission: (origin: string) => void;
}) {
  const kind = 'kind' in error ? error.kind : undefined;
  const origin = 'origin' in error ? error.origin : undefined;
  return (
    <div className="error">
      <p>{error.message}</p>
      {kind === 'file-access' && (
        <>
          <p>
            Để ký file trên máy, bật <b>“Cho phép truy cập vào URL của tệp”</b> (Allow access to
            file URLs) cho KysoQR, rồi tải lại trang này.
          </p>
          <button
            type="button"
            className="btn-outline"
            onClick={() =>
              browser.tabs.create({ url: `chrome://extensions/?id=${browser.runtime.id}` })
            }
          >
            Mở cài đặt extension
          </button>
        </>
      )}
      {kind === 'permission' && origin && (
        <button type="button" className="btn-primary" onClick={() => onGrantPermission(origin)}>
          Cấp quyền và tải lại
        </button>
      )}
    </div>
  );
}

export function SignPanel({
  source,
  fields,
  onFieldsChange,
  selectedId,
  onSelect,
  placing,
  onTogglePlacing,
  onSubmitted,
}: {
  source: PdfSource;
  fields: Field[];
  onFieldsChange: (fields: Field[]) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  /** Đang chờ người dùng bấm vào trang để thêm ô ký. */
  placing: boolean;
  onTogglePlacing: () => void;
  onSubmitted: (item: SignRequestItem) => void;
}) {
  const [documentName, setDocumentName] = useState(() => defaultDocumentName(source.name));
  const [language, setLanguage] = useState<'vi' | 'en'>('vi');
  const [signerKind, setSignerKind] = useState<SignerKind>('individual');
  const [cccd, setCccd] = useState('');
  const [taxCode, setTaxCode] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [rememberCccd, setRememberCccd] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDocumentName(defaultDocumentName(source.name));
    setSubmitting(false);
    setError(null);
  }, [source]);

  useEffect(() => {
    void getSavedCccd().then((v) => {
      if (v) {
        setCccd(v);
        setRememberCccd(true);
      }
    });
  }, []);

  const meta = useMemo(
    () =>
      CreateSignRequestMeta.safeParse({
        documentName,
        language,
        signerKind,
        identificationNumber: cccd.trim() || undefined,
        taxCode: signerKind === 'business' ? taxCode.trim() || undefined : undefined,
        organizationName:
          signerKind === 'business' ? organizationName.trim() || undefined : undefined,
        signatureFields: fields.map((f) => ({ page: f.page, fieldType: f.fieldType, ...f.ratios })),
      }),
    [documentName, language, signerKind, cccd, taxCode, organizationName, fields],
  );
  const problems = meta.success ? [] : [...new Set(meta.error.issues.map(issueText))];

  async function submit() {
    if (!meta.success) return;
    setSubmitting(true);
    setError(null);
    try {
      await setSavedCccd(
        rememberCccd && meta.data.identificationNumber ? meta.data.identificationNumber : null,
      );
      const res = await createSignRequest(source.bytes, source.name, meta.data);
      const item: SignRequestItem = {
        signRequestId: res.signRequestId,
        documentName: meta.data.documentName,
        fileName: source.name,
        qrContent: res.qrContent,
        pushSent: res.pushSent,
        createdAt: new Date().toISOString(),
        expiresAt: res.expiresAt,
        state: res.state,
      };
      onSubmitted(item);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <section className="card">
        <div className="form-row">
          <span className="label">Người ký là ai?</span>
          <div className="segmented" role="radiogroup">
            {(
              [
                ['individual', 'Cá nhân'],
                ['business', 'Doanh nghiệp'],
              ] as const
            ).map(([k, label]) => (
              <button
                key={k}
                type="button"
                role="radio"
                aria-checked={signerKind === k}
                className={signerKind === k ? 'on' : ''}
                onClick={() => setSignerKind(k)}
              >
                {label}
              </button>
            ))}
          </div>
          <p className="info-line">
            <Icon name="info" size={13} /> Nhập thông tin thì gửi yêu cầu ký sang Cas ID.
          </p>
        </div>

        {signerKind === 'business' && (
          <>
            <label className="form-row">
              <span className="label">Mã số thuế doanh nghiệp</span>
              <input
                value={taxCode}
                inputMode="numeric"
                maxLength={14}
                placeholder="0123456789 hoặc 0123456789-001"
                onChange={(e) => setTaxCode(e.target.value.replace(/[^\d-]/g, ''))}
              />
            </label>
            <label className="form-row">
              <span className="label">Tên doanh nghiệp (không bắt buộc)</span>
              <input
                value={organizationName}
                maxLength={255}
                placeholder="CÔNG TY TNHH ..."
                onChange={(e) => setOrganizationName(e.target.value)}
              />
            </label>
          </>
        )}

        <label className="form-row">
          <span className="label">
            {signerKind === 'business' ? 'CCCD người đại diện' : 'CCCD người ký'}
          </span>
          <input
            value={cccd}
            inputMode="numeric"
            maxLength={12}
            placeholder="12 chữ số"
            onChange={(e) => setCccd(e.target.value.replace(/\D/g, ''))}
          />
        </label>
        <p className="hint-box">Để trống thì ký bằng QR.</p>
        {cccd && (
          <label className="check">
            <input
              type="checkbox"
              checked={rememberCccd}
              onChange={(e) => setRememberCccd(e.target.checked)}
            />
            Ghi nhớ CCCD trên máy này
          </label>
        )}
      </section>

      <section className="card">
        <div className="form-row tight">
          <span className="label">Vị trí ký ({fields.length})</span>
          {fields.length > 0 && (
            <ul className="field-list">
              {fields.map((f) => (
                <li
                  key={f.id}
                  className={f.id === selectedId ? 'selected' : ''}
                  onClick={() => onSelect(f.id)}
                >
                  <Icon name={FIELD_ICONS[f.fieldType]} size={14} />
                  <span>
                    {FIELD_LABELS[f.fieldType]} #{fieldNumber(fields, f)} · trang {f.page}
                  </span>
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label="Xoá ô ký"
                    onClick={(e) => {
                      e.stopPropagation();
                      onFieldsChange(fields.filter((x) => x.id !== f.id));
                    }}
                  >
                    <Icon name="trash" size={14} />
                  </button>
                </li>
              ))}
            </ul>
          )}
          <p className="muted small">
            {placing
              ? 'Bấm vào vị trí trên trang PDF để đặt ô ký · Esc để huỷ.'
              : fields.length
                ? 'Kéo ô trên trang để đổi vị trí, kéo góc dưới phải để đổi kích thước.'
                : 'Chưa có ô ký nào.'}
          </p>
          <button type="button" className="btn-outline" onClick={onTogglePlacing}>
            {placing ? (
              <>
                <Icon name="x" size={14} /> Huỷ thêm ô ký
              </>
            ) : (
              <>+ Thêm vị trí ký</>
            )}
          </button>
        </div>
      </section>

      <details className="card options">
        <summary>
          Tuỳ chọn <Icon name="chevronDown" size={14} />
        </summary>
        <label className="form-row">
          <span className="label">Tên tài liệu</span>
          <input
            value={documentName}
            maxLength={240}
            onChange={(e) => setDocumentName(e.target.value)}
          />
          <small>10–240 ký tự, hiển thị trên app Cas ID</small>
        </label>
        <label className="form-row tight">
          <span className="label">Ngôn ngữ trên app Cas ID</span>
          <select value={language} onChange={(e) => setLanguage(e.target.value as 'vi' | 'en')}>
            <option value="vi">Tiếng Việt</option>
            <option value="en">English</option>
          </select>
        </label>
      </details>

      {problems.length > 0 && fields.length > 0 && (
        <ul className="problems">
          {problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      {error && <div className="error">{error}</div>}

      <button
        type="button"
        className="sign-btn"
        disabled={!meta.success || submitting}
        onClick={submit}
      >
        {submitting ? 'Đang gửi yêu cầu…' : 'Gửi yêu cầu ký'}
      </button>
    </>
  );
}

function issueText(issue: { path: (string | number)[]; message: string }) {
  const key = issue.path[0];
  if (key === 'documentName') return 'Tên tài liệu cần 10–240 ký tự.';
  if (key === 'identificationNumber') return 'CCCD phải gồm 12 chữ số.';
  if (key === 'taxCode') return 'Mã số thuế gồm 10 chữ số, hoặc 10-3 chữ số (chi nhánh).';
  if (key === 'signatureFields') return 'Cần ít nhất 1 vị trí ký hợp lệ.';
  return issue.message;
}
