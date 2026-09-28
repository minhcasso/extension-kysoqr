import { useEffect, useMemo, useState } from 'react';
import { getSigningRound, type SigningRound } from '../lib/api';
import type { PDFDocumentProxy } from '../lib/pdf';
import type { HistoryItem } from '../lib/storage';
import { DocumentView } from './DocumentView';

export function Result({
  item,
  signed,
  doc,
  hasSigningRound,
  onNew,
}: {
  item: HistoryItem;
  signed: Uint8Array;
  doc: PDFDocumentProxy;
  hasSigningRound: boolean;
  onNew: () => void;
}) {
  const [round, setRound] = useState<SigningRound | null>(null);
  const url = useMemo(() => URL.createObjectURL(new Blob([signed.slice()], { type: 'application/pdf' })), [signed]);
  useEffect(() => () => URL.revokeObjectURL(url), [url]);

  useEffect(() => {
    if (!hasSigningRound) return;
    getSigningRound(item.signRequestId, item.accessToken).then(setRound, () => setRound(null));
  }, [hasSigningRound, item]);

  const fileName = `${item.fileName.replace(/\.pdf$/i, '')}_signed.pdf`;

  return (
    <div className="layout">
      <DocumentView doc={doc} toolbar={<strong className="ok-text">✓ Đã ký số thành công</strong>} />
      <aside className="panel">
        <h2>Tài liệu đã ký</h2>
        <p>{item.documentName}</p>
        <a className="button primary big" href={url} download={fileName}>
          Tải file đã ký
        </a>

        {round ? (
          <dl className="round">
            <dt>Người ký</dt>
            <dd>{round.signer?.displayName ?? '—'}</dd>
            <dt>Thời điểm ký</dt>
            <dd>{round.signedAt ?? '—'}</dd>
            <dt>Thiết bị</dt>
            <dd>{round.device?.model ?? '—'}</dd>
            <dt>Xác thực</dt>
            <dd>{round.authMethod ?? '—'}</dd>
            <dt>Tổ chức cấp chứng thư</dt>
            <dd>{round.certificate?.issuer?.commonName ?? '—'}</dd>
            <dt>Toàn vẹn tài liệu</dt>
            <dd>{round.certificate?.documentIntegrity ?? '—'}</dd>
          </dl>
        ) : (
          <p className="muted small">
            {hasSigningRound
              ? 'Đang tải thông tin phiên ký…'
              : 'Thông tin phiên ký (người ký, chứng thư số) sẽ có khi backend nhận webhook từ CAS.'}
          </p>
        )}

        <button type="button" className="secondary" onClick={onNew}>
          Ký tài liệu khác
        </button>
      </aside>
    </div>
  );
}
