/** Dữ liệu lưu trên máy người dùng (chrome.storage.local). */

export interface HistoryItem {
  signRequestId: string;
  accessToken: string;
  documentName: string;
  fileName: string;
  qrContent: string;
  pushSent: boolean;
  createdAt: string;
  expiresAt: string;
  state?: string;
}

const HISTORY_KEY = 'history';
const CCCD_KEY = 'identificationNumber';
const MAX_HISTORY = 20;

export async function getHistory(): Promise<HistoryItem[]> {
  const data = await browser.storage.local.get(HISTORY_KEY);
  return (data[HISTORY_KEY] as HistoryItem[] | undefined) ?? [];
}

export async function upsertHistory(item: HistoryItem) {
  const list = (await getHistory()).filter((h) => h.signRequestId !== item.signRequestId);
  await browser.storage.local.set({ [HISTORY_KEY]: [item, ...list].slice(0, MAX_HISTORY) });
}

export async function updateHistoryState(signRequestId: string, state: string) {
  const list = await getHistory();
  const item = list.find((h) => h.signRequestId === signRequestId);
  if (!item || item.state === state) return;
  item.state = state;
  await browser.storage.local.set({ [HISTORY_KEY]: list });
}

export async function getSavedCccd(): Promise<string> {
  const data = await browser.storage.local.get(CCCD_KEY);
  return (data[CCCD_KEY] as string | undefined) ?? '';
}

export async function setSavedCccd(value: string | null) {
  if (value) await browser.storage.local.set({ [CCCD_KEY]: value });
  else await browser.storage.local.remove(CCCD_KEY);
}
