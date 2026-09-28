export default defineBackground(() => {
  // Bấm icon trên tab PDF → mở trang ký riêng của extension ngay bên cạnh.
  browser.action.onClicked.addListener(async (tab) => {
    const job = crypto.randomUUID();
    if (tab.url) {
      // Không đưa URL vào query string; trang viewer đọc lại từ storage.session.
      await browser.storage.session.set({ [`job:${job}`]: { url: tab.url, title: tab.title ?? '' } });
    }
    await browser.tabs.create({
      url: browser.runtime.getURL(`/viewer.html?job=${job}`),
      index: tab.index + 1,
      openerTabId: tab.id,
    });
  });
});
