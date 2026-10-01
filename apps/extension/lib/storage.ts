/** Dữ liệu lưu trên máy người dùng (chrome.storage.local). Không lưu yêu cầu ký nào. */

/** Yêu cầu ký đang xử lý, chỉ nằm trong bộ nhớ của tab (không lưu lại). */
export interface SignRequestItem {
  signRequestId: string;
  documentName: string;
  fileName: string;
  qrContent: string;
  pushSent: boolean;
  createdAt: string;
  expiresAt: string;
  state?: string;
}

const CCCD_KEY = 'identificationNumber';

export async function getSavedCccd(): Promise<string> {
  const data = await browser.storage.local.get(CCCD_KEY);
  return (data[CCCD_KEY] as string | undefined) ?? '';
}

export async function setSavedCccd(value: string | null) {
  if (value) await browser.storage.local.set({ [CCCD_KEY]: value });
  else await browser.storage.local.remove(CCCD_KEY);
}
