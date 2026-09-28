/** Cài đặt "tự mở PDF bằng KysoQR", dùng chung cho background và các trang giao diện. */

const AUTO_OPEN_KEY = 'autoOpenPdf';
export const ALL_SITES = { origins: ['<all_urls>'] };

export async function hasAllSitesPermission(): Promise<boolean> {
  return browser.permissions.contains(ALL_SITES);
}

/** Bật khi người dùng đã chọn bật VÀ vẫn còn quyền (người dùng có thể thu hồi quyền trong Chrome). */
export async function isAutoOpenEnabled(): Promise<boolean> {
  const data = await browser.storage.local.get(AUTO_OPEN_KEY);
  return data[AUTO_OPEN_KEY] === true && (await hasAllSitesPermission());
}

/** Phải gọi trực tiếp trong sự kiện bấm của người dùng (Chrome yêu cầu để xin quyền). */
export async function setAutoOpen(enabled: boolean): Promise<boolean> {
  if (enabled && !(await browser.permissions.request(ALL_SITES))) return false;
  await browser.storage.local.set({ [AUTO_OPEN_KEY]: enabled });
  return enabled;
}

/** Tin nhắn từ trang viewer gửi background. */
export type BackgroundMessage = { type: 'open-in-chrome'; url: string };
