import { useEffect, useMemo, useState } from 'react';
import { getSigningRound, type SigningRound } from '../lib/api';
import type { SignRequestItem } from '../lib/storage';
import { Icon } from './Icon';

export function signedFileName(item: SignRequestItem) {
  return `${item.fileName.replace(/\.pdf$/i, '').replace(/_signed$/i, '')}_signed.pdf`;
}

export function ResultPanel({
  item,
  signed,
  orgIdSigned,
  onNew,
  onContinue,
}: {
  item: SignRequestItem;
  signed: Uint8Array;
  /** Có thì xem được thông tin phiên ký. */
  orgIdSigned: string | null;
  onNew: () => void;
  /** Mở file vừa ký để thêm chữ ký tiếp (người ký khác, con dấu...). */
  onContinue: () => void;
}) {
  const [round, setRound] = useState<SigningRound | null>(null);
  const url = useMemo(
    () => URL.createObjectURL(new Blob([signed.slice()], { type: 'application/pdf' })),
    [signed],
  );
  useEffect(() => () => URL.revokeObjectURL(url), [url]);

  useEffect(() => {
    if (!orgIdSigned) return;
    getSigningRound(orgIdSigned).then(setRound, () => setRound(null));
  }, [orgIdSigned]);

  return (
    <>
      <section className="card status-card done">
        <Icon name="checkCircle" size={40} className="done-icon" />
        <h2 className="status-title">Đã ký số thành công</h2>
        <p className="muted">{item.documentName}</p>
        <a className="sign-btn" href={url} download={signedFileName(item)}>
          <Icon name="download" size={18} /> Tải file đã ký
        </a>
        <p className="muted small">
          KysoQR không lưu file đã ký. Hãy tải về máy để giữ lại bản này.
        </p>
      </section>

      <section className="card">
        <h3 className="card-title">Thông tin phiên ký</h3>
        {round ? (
          <dl className="round">
            <dt>Người ký</dt>
            <dd>{round.signer?.displayName ?? '—'}</dd>
            <dt>Thời điểm ký</dt>
            <dd>{round.signedAt ? new Date(round.signedAt).toLocaleString('vi-VN') : '—'}</dd>
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
            {orgIdSigned
              ? 'Đang tải thông tin phiên ký…'
              : 'Cas ID chưa trả về thông tin phiên ký. Chi tiết chữ ký và chuỗi chứng thư xem ở bảng Xác minh chữ ký (nút ☰).'}
          </p>
        )}
      </section>

      <div className="button-row">
        <button type="button" className="btn-outline" onClick={onContinue}>
          <Icon name="pen" size={14} /> Ký tiếp tài liệu này
        </button>
        <button type="button" className="btn-outline" onClick={onNew}>
          <Icon name="upload" size={14} /> Ký tài liệu khác
        </button>
      </div>
    </>
  );
}
