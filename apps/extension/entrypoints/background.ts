import { isAutoOpenEnabled, type BackgroundMessage } from '../lib/settings';

const VIEWER_PATH = '/viewer.html';
/** URL người dùng vừa chọn "Mở bằng trình xem của Chrome": không chuyển hướng lần kế tiếp. */
const BYPASS_PREFIX = 'bypass:';
const BYPASS_TTL_MS = 30_000;

async function openViewer(tab: { id?: number; index?: number } | undefined, url: string, title = '', replace = false) {
  const job = crypto.randomUUID();
  // Không đưa URL vào query string; trang viewer đọc lại từ storage.session.
  await browser.storage.session.set({ [`job:${job}`]: { url, title } });
  const viewerUrl = browser.runtime.getURL(`${VIEWER_PATH}?job=${job}`);
  if (replace && tab?.id !== undefined) {
    await browser.tabs.update(tab.id, { url: viewerUrl });
  } else {
    await browser.tabs.create({ url: viewerUrl, index: (tab?.index ?? -1) + 1, openerTabId: tab?.id });
  }
}

async function consumeBypass(url: string): Promise<boolean> {
  const key = `${BYPASS_PREFIX}${url}`;
  const data = await browser.storage.session.get(key);
  const at = data[key] as number | undefined;
  if (at === undefined) return false;
  await browser.storage.session.remove(key);
  return Date.now() - at < BYPASS_TTL_MS;
}

// Lỗi nhỏ (vd. tab đã đóng trước khi chuyển) không cần hiện đỏ ở trang Extensions.
const logError = (err: unknown) => console.warn('[KysoQR]', err);

function header(headers: { name: string; value?: string }[] | undefined, name: string) {
  return headers?.find((h) => h.name.toLowerCase() === name)?.value?.toLowerCase() ?? '';
}

export default defineBackground(() => {
  // Bấm icon trên tab PDF → mở trang ký riêng của extension ngay bên cạnh.
  browser.action.onClicked.addListener(async (tab) => {
    await openViewer(tab, tab.url ?? '', tab.title ?? '').catch(logError);
  });

  browser.runtime.onInstalled.addListener(({ reason }) => {
    if (reason === 'install') void browser.runtime.openOptionsPage();
    // Tính năng "Yêu cầu ký gần đây" đã bỏ: xoá lịch sử còn sót lại từ bản cũ.
    void browser.storage.local.remove('history');
  });

  // "Mở bằng trình xem của Chrome" từ trang viewer.
  browser.runtime.onMessage.addListener((msg: BackgroundMessage, sender, sendResponse) => {
    if (msg?.type !== 'open-in-chrome' || sender.tab?.id === undefined) return;
    const tabId = sender.tab.id;
    browser.storage.session
      .set({ [`${BYPASS_PREFIX}${msg.url}`]: Date.now() })
      .then(() => browser.tabs.update(tabId, { url: msg.url }))
      .then(
        () => sendResponse({ ok: true }),
        (err: unknown) => sendResponse({ ok: false, error: String(err) }),
      );
    // Giữ kênh mở để trả lời sau (nếu không Chrome báo "message port closed").
    return true;
  });

  // PDF trên web: nhận ra qua Content-Type (kể cả link không có đuôi .pdf) và chuyển tab
  // sang KysoQR trước khi Chrome hiển thị. Chỉ nhận sự kiện khi đã được cấp quyền mọi trang web.
  browser.webRequest.onHeadersReceived.addListener(
    (details): undefined => {
      if (details.tabId < 0 || details.method !== 'GET') return;
      if (details.statusCode < 200 || details.statusCode >= 300) return;
      const type = header(details.responseHeaders, 'content-type');
      if (!type.startsWith('application/pdf')) return;
      // Máy chủ yêu cầu tải về → để Chrome tải như bình thường.
      if (header(details.responseHeaders, 'content-disposition').startsWith('attachment')) return;

      void (async () => {
        if (!(await isAutoOpenEnabled()) || (await consumeBypass(details.url))) return;
        await openViewer({ id: details.tabId }, details.url, '', true);
      })().catch(logError);
    },
    { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] },
    ['responseHeaders'],
  );

  // PDF trên máy (file://): không có header, nhận ra qua đuôi .pdf.
  // file:// được mở trong tab trước khi mình kịp chuyển, nên nút Back sẽ quay lại file đó.
  // Nhớ file đã chuyển theo từng tab để không chuyển lại khi người dùng bấm Back.
  const redirectedFile = new Map<number, string>();
  browser.tabs.onUpdated.addListener((tabId, change, tab) => {
    const url = change.url;
    if (!url) return;
    if (!/^file:\/\/.*\.pdf$/i.test(url)) {
      redirectedFile.delete(tabId);
      return;
    }
    if (redirectedFile.get(tabId) === url) return;

    void (async () => {
      if (!(await isAutoOpenEnabled()) || (await consumeBypass(url))) return;
      redirectedFile.set(tabId, url);
      await openViewer(tab, url, tab.title ?? '', true);
    })().catch(logError);
  });
  browser.tabs.onRemoved.addListener((tabId) => redirectedFile.delete(tabId));
});
