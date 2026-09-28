import { useEffect, useState } from 'react';
import { Editor } from '../../components/Editor';
import { Result } from '../../components/Result';
import { SigningStatus } from '../../components/SigningStatus';
import { SourcePicker } from '../../components/SourcePicker';
import { isPasswordError, openPdf, type PDFDocumentProxy } from '../../lib/pdf';
import { loadFromFile, loadFromUrl, readJob, type PdfSource } from '../../lib/source';
import type { HistoryItem } from '../../lib/storage';

type Phase =
  | { kind: 'loading' }
  | { kind: 'pick'; error?: Error | null }
  | { kind: 'edit'; source: PdfSource; doc: PDFDocumentProxy }
  | { kind: 'signing'; item: HistoryItem }
  | { kind: 'done'; item: HistoryItem; signed: Uint8Array; doc: PDFDocumentProxy; hasSigningRound: boolean };

const jobId = new URLSearchParams(location.search).get('job');

export function App() {
  const [phase, setPhase] = useState<Phase>({ kind: 'loading' });

  async function openSource(load: () => Promise<PdfSource>) {
    setPhase({ kind: 'loading' });
    try {
      const source = await load();
      const doc = await openPdf(source.bytes);
      document.title = `Ký số – ${source.name}`;
      setPhase({ kind: 'edit', source, doc });
    } catch (e) {
      const error = isPasswordError(e)
        ? new Error('File PDF có mật khẩu, vui lòng bỏ mật khẩu trước khi ký.')
        : e instanceof Error
          ? e
          : new Error(String(e));
      setPhase({ kind: 'pick', error });
    }
  }

  useEffect(() => {
    void readJob(jobId).then((job) => {
      if (!job) return setPhase({ kind: 'pick' });
      void openSource(() => loadFromUrl(job));
    });
  }, []);

  async function grantPermission(origin: string) {
    // Phải gọi trực tiếp trong sự kiện bấm nút.
    const ok = await browser.permissions.request({ origins: [`${origin}/*`] });
    const job = await readJob(jobId);
    if (ok && job) void openSource(() => loadFromUrl(job));
  }

  const restart = () => setPhase({ kind: 'pick' });

  switch (phase.kind) {
    case 'loading':
      return (
        <div className="center-card">
          <div className="spinner" />
          <p>Đang mở file PDF…</p>
        </div>
      );
    case 'pick':
      return (
        <SourcePicker
          error={phase.error}
          onFile={(f) => void openSource(() => loadFromFile(f))}
          onGrantPermission={(o) => void grantPermission(o)}
          onOpenHistory={(item) => setPhase({ kind: 'signing', item })}
        />
      );
    case 'edit':
      return (
        <Editor
          source={phase.source}
          doc={phase.doc}
          onSubmitted={(item) => setPhase({ kind: 'signing', item })}
        />
      );
    case 'signing':
      return (
        <SigningStatus
          item={phase.item}
          onRestart={restart}
          onDone={async (signed, status) => {
            const doc = await openPdf(signed);
            setPhase({ kind: 'done', item: phase.item, signed, doc, hasSigningRound: status.hasSigningRound });
          }}
        />
      );
    case 'done':
      return (
        <Result
          item={phase.item}
          signed={phase.signed}
          doc={phase.doc}
          hasSigningRound={phase.hasSigningRound}
          onNew={restart}
        />
      );
  }
}

