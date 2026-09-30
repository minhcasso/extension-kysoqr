import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  DocumentView,
  MAX_SCALE,
  MIN_SCALE,
  type DocumentControls,
} from '../../components/DocumentView';
import type { Field } from '../../components/PdfViewer';
import { ReaderToolbar, type MenuItem, type VerifyTone } from '../../components/ReaderToolbar';
import { ResultPanel, signedFileName } from '../../components/Result';
import { RecentRequests, SignDrawer } from '../../components/SignDrawer';
import { SignatureSidebar, VERDICTS } from '../../components/SignatureSidebar';
import { SigningStatus } from '../../components/SigningStatus';
import { SignPanel, SourceErrorBox, UploadCard } from '../../components/SignPanel';
import { isPasswordError, openPdf, type PDFDocumentProxy } from '../../lib/pdf';
import { defaultField } from '../../lib/placement';
import type { BackgroundMessage } from '../../lib/settings';
import { loadFromFile, loadFromUrl, readJob, type PdfSource } from '../../lib/source';
import type { HistoryItem } from '../../lib/storage';
import { useSignatures, verdict } from '../../lib/useSignatures';

interface OpenDoc {
  source: PdfSource;
  pdf: PDFDocumentProxy;
  originalUrl?: string;
}

type SignStage =
  | { kind: 'edit' }
  | { kind: 'signing'; item: HistoryItem }
  | { kind: 'done'; item: HistoryItem; signed: Uint8Array; hasSigningRound: boolean };

type Drawer = 'closed' | 'sign' | 'history';

const jobId = new URLSearchParams(location.search).get('job');
const STEP: Record<SignStage['kind'], number> = { edit: 0, signing: 1, done: 2 };
const TONE_RANK: VerifyTone[] = ['bad', 'warn', 'neutral', 'ok'];

export function App() {
  const [doc, setDoc] = useState<OpenDoc | null>(null);
  const [loading, setLoading] = useState<string | null>('Đang mở file PDF…');
  const [sourceError, setSourceError] = useState<Error | null>(null);

  const [drawer, setDrawer] = useState<Drawer>('closed');
  const [sign, setSign] = useState<SignStage>({ kind: 'edit' });
  const [fields, setFields] = useState<Field[]>([]);
  const [placing, setPlacing] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [scale, setScale] = useState<number | null>(null);
  const [userZoomed, setUserZoomed] = useState(false);
  const [page, setPage] = useState(1);
  const controls = useRef<DocumentControls | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const signatures = useSignatures(doc?.source.bytes ?? null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // PDF có chữ ký số → tự mở bảng xác minh (một lần cho mỗi file); không có → không hiện gì.
  const autoOpenedFor = useRef<Uint8Array | null>(null);
  const hasSignatures = !signatures.loading && signatures.items.length > 0;
  useEffect(() => {
    const bytes = doc?.source.bytes ?? null;
    if (hasSignatures && bytes && autoOpenedFor.current !== bytes) {
      autoOpenedFor.current = bytes;
      setSidebarOpen(true);
    }
  }, [hasSignatures, doc]);

  const showDoc = useCallback((next: OpenDoc) => {
    document.title = next.source.name;
    setDoc(next);
    setSidebarOpen(false);
    setUserZoomed(false);
    setFields([]);
    setSelectedId(null);
    setPlacing(false);
  }, []);

  async function openSource(load: () => Promise<PdfSource>, originalUrl?: string) {
    setLoading('Đang mở file PDF…');
    setSourceError(null);
    try {
      const source = await load();
      const pdf = await openPdf(source.bytes);
      showDoc({ source, pdf, originalUrl });
      setSign({ kind: 'edit' });
      setDrawer('closed');
    } catch (e) {
      setSourceError(
        isPasswordError(e)
          ? new Error('File PDF có mật khẩu, vui lòng bỏ mật khẩu trước khi ký.')
          : e instanceof Error
            ? e
            : new Error(String(e)),
      );
    } finally {
      setLoading(null);
    }
  }

  useEffect(() => {
    void readJob(jobId).then((job) => {
      if (!job) return setLoading(null);
      void openSource(() => loadFromUrl(job), job.url);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function grantPermission(origin: string) {
    // Phải gọi trực tiếp trong sự kiện bấm nút.
    const ok = await browser.permissions.request({ origins: [`${origin}/*`] });
    const job = await readJob(jobId);
    if (ok && job) void openSource(() => loadFromUrl(job), job.url);
  }

  const openFile = (file: File) => void openSource(() => loadFromFile(file));

  const zoom = useCallback((factor: number) => {
    setUserZoomed(true);
    setScale((s) =>
      s ? Math.round(Math.min(MAX_SCALE, Math.max(MIN_SCALE, s * factor)) * 100) / 100 : s,
    );
  }, []);

  const fit = () => {
    setUserZoomed(false);
    controls.current?.fit();
  };

  /** Đặt sẵn một ô chữ ký gần cuối trang đang đọc và cuộn nhẹ để ô đó hiện ra. */
  async function placeDefault(current: Field[]) {
    if (!doc) return;
    const field = await defaultField(doc.pdf, page, current);
    setFields([...current, field]);
    setSelectedId(field.id);
    // Chờ bảng ký mở xong (khung xem hẹp lại, trang được vẽ lại theo tỷ lệ mới).
    setTimeout(() => {
      document
        .querySelector(`[data-field-id="${field.id}"]`)
        ?.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'smooth' });
    }, 350);
  }

  function onSignClick() {
    if (drawer === 'sign') return setDrawer('closed');
    setDrawer('sign');
    if (sign.kind === 'done') {
      // File đang xem là bản vừa ký → ký tiếp trên bản đó.
      setSign({ kind: 'edit' });
      void placeDefault([]);
      return;
    }
    if (sign.kind === 'edit' && fields.length === 0) void placeDefault(fields);
  }

  async function onSigned(item: HistoryItem, signed: Uint8Array, hasSigningRound: boolean) {
    showDoc({ source: { bytes: signed, name: signedFileName(item) }, pdf: await openPdf(signed) });
    setSign({ kind: 'done', item, signed, hasSigningRound });
    setDrawer('sign');
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && (e.key === '=' || e.key === '+')) {
        e.preventDefault();
        zoom(1.1);
      } else if (mod && e.key === '-') {
        e.preventDefault();
        zoom(1 / 1.1);
      } else if (mod && e.key === '0') {
        e.preventDefault();
        fit();
      } else if (e.key === 'Escape') {
        setPlacing(false);
      } else if (
        (e.key === 'Delete' || e.key === 'Backspace') &&
        selectedId &&
        sign.kind === 'edit' &&
        drawer === 'sign' &&
        !isTyping(e)
      ) {
        setFields((fs) => fs.filter((f) => f.id !== selectedId));
        setSelectedId(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, sign.kind, drawer, zoom]);

  const downloadUrl = useMemo(
    () =>
      doc
        ? URL.createObjectURL(new Blob([doc.source.bytes.slice()], { type: 'application/pdf' }))
        : null,
    [doc],
  );
  useEffect(() => () => void (downloadUrl && URL.revokeObjectURL(downloadUrl)), [downloadUrl]);

  const verifyTone = useMemo<VerifyTone>(() => {
    const tones = signatures.items.map((it) => VERDICTS[verdict(it)].tone as VerifyTone);
    return TONE_RANK.find((t) => tones.includes(t)) ?? 'neutral';
  }, [signatures.items]);

  const menu: MenuItem[] = [
    { label: 'Mở file PDF khác', icon: 'upload', onClick: () => fileInput.current?.click() },
    ...(doc?.originalUrl
      ? [
          {
            label: 'Mở bằng trình xem của Chrome',
            icon: 'external' as const,
            onClick: () => {
              const url = doc.originalUrl!;
              browser.runtime
                .sendMessage({ type: 'open-in-chrome', url } satisfies BackgroundMessage)
                .catch(() => (location.href = url));
            },
          },
        ]
      : []),
    { label: 'Yêu cầu ký gần đây', icon: 'history', onClick: () => setDrawer('history') },
    { label: 'Cài đặt', icon: 'settings', onClick: () => void browser.runtime.openOptionsPage() },
  ];

  const signMode = drawer === 'sign' && sign.kind !== 'done';
  const editing = signMode && sign.kind === 'edit' && doc !== null;

  let drawerContent: ReactNode = null;
  if (sign.kind === 'edit' && doc) {
    drawerContent = (
      <SignPanel
        source={doc.source}
        fields={fields}
        onFieldsChange={setFields}
        selectedId={selectedId}
        onSelect={setSelectedId}
        placing={placing}
        onTogglePlacing={() => setPlacing((p) => !p)}
        onSubmitted={(item) => {
          setPlacing(false);
          setSign({ kind: 'signing', item });
        }}
      />
    );
  } else if (sign.kind === 'signing') {
    drawerContent = (
      <SigningStatus
        item={sign.item}
        onRestart={() => setSign({ kind: 'edit' })}
        onDone={(signed, status) => void onSigned(sign.item, signed, status.hasSigningRound)}
      />
    );
  } else if (sign.kind === 'done') {
    drawerContent = (
      <ResultPanel
        item={sign.item}
        signed={sign.signed}
        hasSigningRound={sign.hasSigningRound}
        onNew={() => fileInput.current?.click()}
        onContinue={() => {
          setSign({ kind: 'edit' });
          void placeDefault([]);
        }}
      />
    );
  }

  return (
    <div className="reader">
      <input
        ref={fileInput}
        type="file"
        accept="application/pdf,.pdf"
        hidden
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file) openFile(file);
        }}
      />
      <ReaderToolbar
        fileName={doc?.source.name ?? null}
        verify={
          signatures.items.length > 0
            ? {
                count: signatures.items.length,
                tone: verifyTone,
                open: sidebarOpen,
                onToggle: () => setSidebarOpen((o) => !o),
              }
            : null
        }
        viewer={
          doc
            ? {
                page,
                numPages: doc.pdf.numPages,
                onJump: (p) => controls.current?.jump(p),
                scale,
                onZoom: zoom,
                onFit: fit,
              }
            : null
        }
        download={doc && downloadUrl ? { url: downloadUrl, name: doc.source.name } : null}
        menu={menu}
        onSign={doc ? onSignClick : null}
        signing={drawer === 'sign'}
      />

      <div className="reader-body">
        {sidebarOpen && signatures.items.length > 0 && (
          <SignatureSidebar signatures={signatures} onClose={() => setSidebarOpen(false)} />
        )}

        <main
          className="doc"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const file = e.dataTransfer.files[0];
            if (file) openFile(file);
          }}
        >
          {editing && placing && (
            <div className="placing-hint">
              Bấm vào vị trí trên trang để đặt ô ký · <kbd>Esc</kbd> để huỷ
            </div>
          )}
          <DocumentView
            doc={doc?.pdf ?? null}
            scale={scale}
            onScale={setScale}
            onZoom={zoom}
            onPageChange={setPage}
            controlsRef={controls}
            autoFit={!userZoomed}
            fields={signMode ? fields : []}
            onFieldsChange={editing ? setFields : undefined}
            placing={editing && placing ? 'SIGNATURE' : null}
            onPlaced={(f) => {
              setFields((fs) => [...fs, f]);
              setSelectedId(f.id);
              setPlacing(false);
            }}
            selectedId={selectedId}
            onSelect={setSelectedId}
            empty={
              loading ? (
                <div className="doc-empty">
                  <div className="spinner" />
                  <p>{loading}</p>
                </div>
              ) : (
                <div className="doc-empty">
                  <UploadCard onFile={openFile} />
                  {sourceError && (
                    <SourceErrorBox
                      error={sourceError}
                      onGrantPermission={(o) => void grantPermission(o)}
                    />
                  )}
                </div>
              )
            }
          />
        </main>

        {/* Luôn giữ bảng ký trong cây để không mất dữ liệu đã nhập khi đóng rồi mở lại. */}
        <div className={`drawer-slot ${drawer === 'sign' ? 'open' : ''}`}>
          {drawerContent && (
            <SignDrawer step={STEP[sign.kind]} onClose={() => setDrawer('closed')}>
              {drawerContent}
            </SignDrawer>
          )}
        </div>
        {drawer === 'history' && (
          <div className="drawer-slot open">
            <SignDrawer step={null} title="Yêu cầu ký gần đây" onClose={() => setDrawer('closed')}>
              <RecentRequests
                onOpen={(item) => {
                  setFields([]);
                  setPlacing(false);
                  setSign({ kind: 'signing', item });
                  setDrawer('sign');
                }}
              />
            </SignDrawer>
          </div>
        )}
      </div>
    </div>
  );
}

function isTyping(e: KeyboardEvent) {
  const el = e.target as HTMLElement | null;
  return el?.tagName === 'INPUT' || el?.tagName === 'SELECT' || el?.tagName === 'TEXTAREA';
}
