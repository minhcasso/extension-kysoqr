import { CreateSignRequestMeta, type FieldType } from '@kysoqr/shared';
import { useEffect, useMemo, useState } from 'react';
import { createSignRequest } from '../lib/api';
import type { PDFDocumentProxy } from '../lib/pdf';
import type { BackgroundMessage } from '../lib/settings';
import type { PdfSource } from '../lib/source';
import { getSavedCccd, setSavedCccd, upsertHistory, type HistoryItem } from '../lib/storage';
import { DocumentView } from './DocumentView';
import { FIELD_LABELS, type Field } from './PdfViewer';

function defaultDocumentName(fileName: string) {
  const base = fileName.replace(/\.pdf$/i, '').trim();
  return base.length >= 10 ? base.slice(0, 240) : `Tài liệu ký số - ${base || 'KysoQR'}`;
}

export function Editor({
  source,
  doc,
  originalUrl,
  onSubmitted,
}: {
  source: PdfSource;
  doc: PDFDocumentProxy;
  /** URL gốc của file (khi mở từ một tab), để quay về trình xem PDF của Chrome. */
  originalUrl?: string;
  onSubmitted: (item: HistoryItem) => void;
}) {
  const [fields, setFields] = useState<Field[]>([]);
  const [placing, setPlacing] = useState<FieldType | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [documentName, setDocumentName] = useState(() => defaultDocumentName(source.name));
  const [cccd, setCccd] = useState('');
  const [rememberCccd, setRememberCccd] = useState(false);
  const [language, setLanguage] = useState<'vi' | 'en'>('vi');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void getSavedCccd().then((v) => {
      if (v) {
        setCccd(v);
        setRememberCccd(true);
      }
    });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setPlacing(null);
      if ((e.key === 'Delete' || e.key === 'Backspace') && selectedId && !isTyping(e)) {
        setFields((fs) => fs.filter((f) => f.id !== selectedId));
        setSelectedId(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedId]);

  const meta = useMemo(
    () =>
      CreateSignRequestMeta.safeParse({
        documentName,
        language,
        identificationNumber: cccd.trim() || undefined,
        signatureFields: fields.map((f) => ({ page: f.page, fieldType: f.fieldType, ...f.ratios })),
      }),
    [documentName, language, cccd, fields],
  );

  const problems = meta.success ? [] : [...new Set(meta.error.issues.map(issueText))];

  async function submit() {
    if (!meta.success) return;
    setSubmitting(true);
    setError(null);
    try {
      await setSavedCccd(rememberCccd && meta.data.identificationNumber ? meta.data.identificationNumber : null);
      const res = await createSignRequest(source.bytes, source.name, meta.data);
      const item: HistoryItem = {
        signRequestId: res.signRequestId,
        accessToken: res.accessToken,
        documentName: meta.data.documentName,
        fileName: source.name,
        qrContent: res.qrContent,
        pushSent: res.pushSent,
        createdAt: new Date().toISOString(),
        expiresAt: res.expiresAt,
        state: res.state,
      };
      await upsertHistory(item);
      onSubmitted(item);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setSubmitting(false);
    }
  }

  const addButton = (type: FieldType) => (
    <button
      type="button"
      className={placing === type ? 'primary' : 'secondary'}
      onClick={() => setPlacing(placing === type ? null : type)}
    >
      + {FIELD_LABELS[type]}
    </button>
  );

  return (
    <div className="layout">
      <DocumentView
        doc={doc}
        fields={fields}
        onFieldsChange={setFields}
        placing={placing}
        onPlaced={(f) => {
          setFields((fs) => [...fs, f]);
          setSelectedId(f.id);
          setPlacing(null);
        }}
        selectedId={selectedId}
        onSelect={setSelectedId}
        toolbar={
          <>
            {addButton('SIGNATURE')}
            {addButton('INITIAL')}
            {addButton('STAMP')}
            {placing && <span className="hint">Bấm vào vị trí trên trang để đặt ô · Esc để huỷ</span>}
            {originalUrl && (
              <button
                type="button"
                className="ghost"
                title="Chỉ đọc file bằng trình xem PDF mặc định của Chrome"
                onClick={() =>
                  browser.runtime
                    .sendMessage({ type: 'open-in-chrome', url: originalUrl } satisfies BackgroundMessage)
                    .catch(() => (location.href = originalUrl))
                }
              >
                Mở bằng trình xem của Chrome
              </button>
            )}
          </>
        }
      />

      <aside className="panel">
        <h2>Thông tin ký số</h2>

        <label className="field-row">
          <span>Tên tài liệu</span>
          <input value={documentName} maxLength={240} onChange={(e) => setDocumentName(e.target.value)} />
          <small>10–240 ký tự, hiển thị trên app Cas ID</small>
        </label>

        <label className="field-row">
          <span>Số CCCD người ký (không bắt buộc)</span>
          <input
            value={cccd}
            inputMode="numeric"
            maxLength={12}
            placeholder="12 chữ số"
            onChange={(e) => setCccd(e.target.value.replace(/\D/g, ''))}
          />
          <small>Có CCCD: gửi thông báo thẳng tới app Cas ID. Không có: chỉ quét QR.</small>
        </label>
        {cccd && (
          <label className="check">
            <input type="checkbox" checked={rememberCccd} onChange={(e) => setRememberCccd(e.target.checked)} />
            Ghi nhớ CCCD trên máy này
          </label>
        )}

        <label className="field-row">
          <span>Ngôn ngữ trên Cas ID</span>
          <select value={language} onChange={(e) => setLanguage(e.target.value as 'vi' | 'en')}>
            <option value="vi">Tiếng Việt</option>
            <option value="en">English</option>
          </select>
        </label>

        <h3>Vị trí ký ({fields.length})</h3>
        {fields.length === 0 ? (
          <p className="muted">Chọn “+ Chữ ký” trên thanh công cụ rồi bấm vào trang PDF để đặt ô ký.</p>
        ) : (
          <ul className="field-list">
            {fields.map((f, i) => (
              <li key={f.id} className={f.id === selectedId ? 'selected' : ''} onClick={() => setSelectedId(f.id)}>
                <span>
                  {i + 1}. Trang {f.page}
                </span>
                <select
                  value={f.fieldType}
                  onChange={(e) =>
                    setFields((fs) =>
                      fs.map((x) => (x.id === f.id ? { ...x, fieldType: e.target.value as FieldType } : x)),
                    )
                  }
                >
                  {Object.entries(FIELD_LABELS).map(([v, label]) => (
                    <option key={v} value={v}>
                      {label}
                    </option>
                  ))}
                </select>
                <button type="button" className="ghost" onClick={() => setFields((fs) => fs.filter((x) => x.id !== f.id))}>
                  Xoá
                </button>
              </li>
            ))}
          </ul>
        )}

        {problems.length > 0 && fields.length > 0 && (
          <ul className="problems">
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        )}
        {error && <div className="error">{error}</div>}

        <button type="button" className="primary big" disabled={!meta.success || submitting} onClick={submit}>
          {submitting ? 'Đang gửi yêu cầu…' : 'Ký số'}
        </button>
      </aside>
    </div>
  );
}

function issueText(issue: { path: (string | number)[]; message: string }) {
  const key = issue.path[0];
  if (key === 'documentName') return 'Tên tài liệu cần 10–240 ký tự.';
  if (key === 'identificationNumber') return 'CCCD phải gồm 12 chữ số.';
  if (key === 'signatureFields') return 'Cần ít nhất 1 vị trí ký hợp lệ.';
  return issue.message;
}

function isTyping(e: KeyboardEvent) {
  const el = e.target as HTMLElement | null;
  return el?.tagName === 'INPUT' || el?.tagName === 'SELECT' || el?.tagName === 'TEXTAREA';
}
