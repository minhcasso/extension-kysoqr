import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  DocumentView,
  MAX_SCALE,
  MIN_SCALE,
  type DocumentControls,
  type FitMode,
} from '../../components/DocumentView';
import type { Field } from '../../components/PdfViewer';
import { ReaderToolbar, type MenuItem, type VerifyTone } from '../../components/ReaderToolbar';
import { ResultPanel, signedFileName } from '../../components/Result';
import { SignDrawer } from '../../components/SignDrawer';
import { SignatureSidebar, VERDICTS, type SidebarPanel } from '../../components/SignatureSidebar';
import { SigningStatus } from '../../components/SigningStatus';
import { SignPanel, SourceErrorBox, UploadCard } from '../../components/SignPanel';
import { isPasswordError, openPdf, type PDFDocumentProxy } from '../../lib/pdf';
import { defaultField } from '../../lib/placement';
import type { BackgroundMessage } from '../../lib/settings';
import { loadFromFile, loadFromUrl, readJob, type PdfSource } from '../../lib/source';
import type { SignRequestItem } from '../../lib/storage';
import { scrollWithin } from '../../lib/scroll';
import { useSignatures, verdict } from '../../lib/useSignatures';
import { printPdf } from '../../lib/print';
import { loadTabDoc, saveTabDoc } from '../../lib/docCache';
import { DocumentProperties } from '../../components/DocumentProperties';

interface OpenDoc {
  source: PdfSource;
  pdf: PDFDocumentProxy;
  originalUrl?: string;
}

type SignStage =
  | { kind: 'edit' }
  | { kind: 'signing'; item: SignRequestItem }
  | { kind: 'done'; item: SignRequestItem; signed: Uint8Array; orgIdSigned: string | null };

type Drawer = 'closed' | 'sign';

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
  const [fitMode, setFitMode] = useState<FitMode>('width');
  const [rotation, setRotation] = useState(0);
  const [twoPage, setTwoPage] = useState(false);
  const [annotations, setAnnotations] = useState(true);
  const [printing, setPrinting] = useState(false);
  const [showProps, setShowProps] = useState(false);
  const [page, setPage] = useState(1);
  const controls = useRef<DocumentControls | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const signatures = useSignatures(doc?.source.bytes ?? null);
  const [panel, setPanel] = useState<'none' | SidebarPanel>('none');

  // PDF có chữ ký số → tự mở bảng xác minh (một lần cho mỗi file); không có → không hiện gì.
  const autoOpenedFor = useRef<Uint8Array | null>(null);
  const hasSignatures = !signatures.loading && signatures.items.length > 0;
  useEffect(() => {
    const bytes = doc?.source.bytes ?? null;
    if (hasSignatures && bytes && autoOpenedFor.current !== bytes) {
      autoOpenedFor.current = bytes;
      setPanel('verify');
    }
  }, [hasSignatures, doc]);

  const showDoc = useCallback((next: OpenDoc) => {
    document.title = next.source.name;
    setDoc(next);
    // Giữ tài liệu (cả bản vừa ký) để tải lại trang vẫn mở đúng file này.
    void saveTabDoc({
      name: next.source.name,
      bytes: next.source.bytes,
      originalUrl: next.originalUrl,
    });
    setPanel('none');
    setRotation(0);
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
    void (async () => {
      // Tải lại trang: mở lại đúng tài liệu tab đang xem (file chọn từ máy, bản vừa ký...).
      const cached = await loadTabDoc();
      if (cached) {
        return openSource(async () => ({ bytes: cached.bytes, name: cached.name }), cached.originalUrl);
      }
      const job = await readJob(jobId);
      if (!job) return setLoading(null);
      void openSource(() => loadFromUrl(job), job.url);
    })();
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

  /** Đặt tỷ lệ từ ô % trên thanh công cụ. */
  const setZoom = (value: number) => {
    setUserZoomed(true);
    setScale(Math.round(Math.min(MAX_SCALE, Math.max(MIN_SCALE, value)) * 100) / 100);
  };

  /** Như Chrome: chuyển giữa vừa chiều ngang và vừa trang (DocumentView tự vừa khít lại). */
  const toggleFit = () => {
    setUserZoomed(false);
    setFitMode((m) => (m === 'width' ? 'page' : 'width'));
  };

  /** Xoay chỉ để xem: tỷ lệ ô ký tính trên trang gốc nên file gửi ký không đổi. */
  const rotate = (delta: number) => setRotation((r) => (r + delta + 360) % 360);

  /** Đặt sẵn một ô chữ ký gần cuối trang đang đọc và cuộn nhẹ để ô đó hiện ra. */
  async function placeDefault(current: Field[]) {
    if (!doc) return;
    const field = await defaultField(doc.pdf, page, current);
    setFields([...current, field]);
    setSelectedId(field.id);
    // Chờ bảng ký mở xong (khung xem hẹp lại, trang được vẽ lại theo tỷ lệ mới).
    setTimeout(() => {
      scrollWithin(
        document.querySelector<HTMLElement>('.doc-scroll'),
        document.querySelector(`[data-field-id="${field.id}"]`),
        'center',
        'smooth',
      );
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

  async function onSigned(item: SignRequestItem, signed: Uint8Array, orgIdSigned: string | null) {
    showDoc({ source: { bytes: signed, name: signedFileName(item) }, pdf: await openPdf(signed) });
    setSign({ kind: 'done', item, signed, orgIdSigned });
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
      } else if (mod && e.key === '\\') {
        e.preventDefault();
        toggleFit();
      } else if (mod && (e.key === '[' || e.key === ']')) {
        e.preventDefault();
        rotate(e.key === '[' ? -90 : 90);
      } else if (mod && e.key.toLowerCase() === 'p') {
        // Thay lệnh in của trình duyệt (vốn in cả giao diện) bằng in nội dung tài liệu.
        e.preventDefault();
        printRef.current();
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


  const verifyTone = useMemo<VerifyTone>(() => {
    const tones = signatures.items.map((it) => VERDICTS[verdict(it)].tone as VerifyTone);
    return TONE_RANK.find((t) => tones.includes(t)) ?? 'neutral';
  }, [signatures.items]);

  // Nút ☰: PDF chưa ký thì như trình xem PDF thường (không có mục xác minh).
  const sidebarItems: MenuItem[] = [
    {
      label: 'Thu nhỏ',
      icon: 'sidebarClose',
      checked: panel === 'none',
      onClick: () => setPanel('none'),
    },
    ...(signatures.items.length > 0
      ? [
          {
            label: 'Xác minh chữ ký',
            icon: 'shield' as const,
            checked: panel === 'verify',
            onClick: () => setPanel('verify'),
          },
        ]
      : []),
    {
      label: 'Preview',
      icon: 'pages',
      checked: panel === 'pages',
      onClick: () => setPanel('pages'),
    },
  ];

  function print() {
    if (!doc || printing) return;
    setPrinting(true);
    printPdf(doc.pdf)
      .catch((e: unknown) => alert(e instanceof Error ? e.message : String(e)))
      .finally(() => setPrinting(false));
  }
  // Phím tắt Ctrl+P đăng ký một lần, nên luôn gọi bản `print` mới nhất (đúng tài liệu đang mở).
  const printRef = useRef(print);
  printRef.current = print;

  // Giống menu ⋮ của trình xem PDF Chrome, rồi tới các mục riêng của KysoQR.
  const menu: MenuItem[] = [
    ...(doc
      ? [
          {
            label: 'Xem 2 trang',
            icon: 'columns' as const,
            checked: twoPage,
            onClick: () => setTwoPage((v) => !v),
          },
          {
            label: 'Chú thích',
            icon: 'message' as const,
            checked: annotations,
            onClick: () => setAnnotations((v) => !v),
          },
          {
            label: 'Trình chiếu',
            icon: 'present' as const,
            divider: true,
            onClick: () => controls.current?.present(),
          },
          {
            label: 'Thuộc tính tài liệu',
            icon: 'fileInfo' as const,
            onClick: () => setShowProps(true),
          },
        ]
      : []),
    {
      label: 'Mở file PDF khác',
      icon: 'upload',
      divider: Boolean(doc),
      onClick: () => fileInput.current?.click(),
    },
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
        onDone={(signed, orgIdSigned) => void onSigned(sign.item, signed, orgIdSigned)}
      />
    );
  } else if (sign.kind === 'done') {
    drawerContent = (
      <ResultPanel
        item={sign.item}
        signed={sign.signed}
        orgIdSigned={sign.orgIdSigned}
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
        sidebar={
          doc
            ? {
                items: sidebarItems,
                open: panel !== 'none',
                count: signatures.items.length,
                tone: verifyTone,
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
                onSetScale: setZoom,
                fitMode,
                onToggleFit: toggleFit,
                onRotate: rotate,
              }
            : null
        }
        download={doc ? { bytes: doc.source.bytes, name: doc.source.name } : null}
        print={doc ? { onPrint: print, busy: printing } : null}
        menu={menu}
        onSign={doc ? onSignClick : null}
        signing={drawer === 'sign'}
      />

      <div className="reader-body">
        {doc && panel !== 'none' && (
          <SignatureSidebar
            panel={panel}
            signatures={signatures}
            doc={doc.pdf}
            page={page}
            onJump={(p) => controls.current?.jump(p)}
            rotation={rotation}
            annotations={annotations}
            onClose={() => setPanel('none')}
          />
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
            fitMode={fitMode}
            rotation={rotation}
            twoPage={twoPage}
            annotations={annotations}
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

        {showProps && doc && (
          <DocumentProperties
            doc={doc.pdf}
            fileName={doc.source.name}
            fileSize={doc.source.bytes.length}
            onClose={() => setShowProps(false)}
          />
        )}

        {/* Luôn giữ bảng ký trong cây để không mất dữ liệu đã nhập khi đóng rồi mở lại. */}
        <div className={`drawer-slot ${drawer === 'sign' ? 'open' : ''}`}>
          {drawerContent && (
            <SignDrawer step={STEP[sign.kind]} onClose={() => setDrawer('closed')}>
              {drawerContent}
            </SignDrawer>
          )}
        </div>
      </div>
    </div>
  );
}

function isTyping(e: KeyboardEvent) {
  const el = e.target as HTMLElement | null;
  return el?.tagName === 'INPUT' || el?.tagName === 'SELECT' || el?.tagName === 'TEXTAREA';
}
