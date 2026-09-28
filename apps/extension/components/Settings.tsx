import { useEffect, useState } from 'react';
import { isAutoOpenEnabled, setAutoOpen } from '../lib/settings';
import { getSavedCccd, setSavedCccd } from '../lib/storage';

export function Settings() {
  const [autoOpen, setAutoOpenState] = useState<boolean | null>(null);
  const [fileAccess, setFileAccess] = useState(true);
  const [cccd, setCccd] = useState('');
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    void isAutoOpenEnabled().then(setAutoOpenState);
    void browser.extension.isAllowedFileSchemeAccess().then(setFileAccess);
    void getSavedCccd().then(setCccd);
  }, []);

  async function toggle(enabled: boolean) {
    setMessage(null);
    const result = await setAutoOpen(enabled);
    setAutoOpenState(result);
    if (enabled && !result) setMessage('Bạn chưa cấp quyền, nên KysoQR chưa thể tự mở file PDF.');
  }

  return (
    <div className="center-card wide">
      <h1>Cài đặt KysoQR</h1>

      <section className="setting">
        <label className="switch-row">
          <span>
            <strong>Tự mở file PDF bằng KysoQR</strong>
            <small>
              Khi mở một file PDF trên Chrome, KysoQR sẽ hiển thị file để bạn ký số ngay. Vẫn có nút “Mở bằng
              trình xem của Chrome” nếu chỉ muốn đọc.
            </small>
          </span>
          <input
            type="checkbox"
            className="switch"
            disabled={autoOpen === null}
            checked={Boolean(autoOpen)}
            onChange={(e) => void toggle(e.target.checked)}
          />
        </label>
        {!autoOpen && (
          <p className="muted small">
            Khi bật, Chrome sẽ hỏi quyền truy cập các trang web. KysoQR chỉ dùng quyền này để nhận ra file PDF
            bạn mở và tải file đó về trang ký; nội dung file chỉ được gửi đi khi bạn bấm “Ký số”.
          </p>
        )}
        {message && <div className="error">{message}</div>}
      </section>

      <section className="setting">
        <strong>File PDF trên máy</strong>
        {fileAccess ? (
          <p className="muted small">Đã cho phép. KysoQR mở được file PDF trên máy (file://).</p>
        ) : (
          <>
            <p className="muted small">
              Để ký file PDF trên máy, bật <b>“Cho phép truy cập vào URL của tệp”</b> (Allow access to file URLs)
              trong trang chi tiết extension.
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
      </section>

      {cccd && (
        <section className="setting">
          <strong>CCCD đã lưu</strong>
          <p className="muted small">•••••••{cccd.slice(-5)}</p>
          <button
            type="button"
            className="secondary"
            onClick={() => void setSavedCccd(null).then(() => setCccd(''))}
          >
            Xoá CCCD đã lưu
          </button>
        </section>
      )}
    </div>
  );
}
