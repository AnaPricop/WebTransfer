import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { buildRoomUrl, consumeRootKey, formatCode, type Role } from '../lib/crypto';
import { pickDirectory, sinkCapabilities, type FsDirHandle } from '../lib/fileSink';
import { statusLabel, t } from '../strings';
import { transferKey, useWebBeam, type TextItem } from '../useWebBeam';
import { LinkDiagram } from './LinkDiagram';
import { TransferRow } from './TransferRow';

const signalingUrl: string =
  import.meta.env.VITE_SIGNALING_URL || `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;

function readCode(roomId: string): string | null {
  try {
    return sessionStorage.getItem(`webbeam:code:${roomId}`);
  } catch {
    return null;
  }
}

export function Room({ roomId }: { roomId: string }) {
  const [init] = useState(() => {
    const secure = typeof crypto !== 'undefined' && !!crypto.subtle;
    return {
      secure,
      key: secure ? consumeRootKey(roomId) : null,
      role: (sessionStorage.getItem(`webbeam:role:${roomId}`) === 'host' ? 'host' : 'guest') as Role,
      code: readCode(roomId),
    };
  });
  const [dir, setDir] = useState<FsDirHandle | null>(null);
  const wb = useWebBeam({ roomId, rootKey: init.key, role: init.role, signalingUrl, directory: dir });

  const connected = wb.state === 'connected';
  const link = init.key ? buildRoomUrl(location.origin, roomId, init.key) : '';
  const { sendFiles } = wb;

  // capturi de ecran / fisiere lipite cu Ctrl+V
  useEffect(() => {
    if (!connected) return;
    const onPaste = (e: ClipboardEvent) => {
      const files = [...(e.clipboardData?.files ?? [])];
      if (files.length) {
        e.preventDefault();
        sendFiles(files);
      }
    };
    window.addEventListener('paste', onPaste);
    return () => window.removeEventListener('paste', onPaste);
  }, [connected, sendFiles]);

  if (!init.secure || !init.key) {
    return (
      <main className="mx-auto max-w-2xl px-5 pt-8 pb-16">
        <a href="/" className="text-lg font-bold tracking-tight">
          WebBeam
        </a>
        <p role="alert" className="mt-10 text-bad">
          {init.secure ? t.noKey : t.insecure}
        </p>
        <a href="/" className="btn-quiet mt-6">
          {t.home}
        </a>
      </main>
    );
  }

  const dot =
    wb.state === 'connected'
      ? 'bg-ok'
      : wb.state === 'failed'
        ? 'bg-bad'
        : wb.state === 'closed' || wb.state === 'idle'
          ? 'bg-muted'
          : 'bg-beam';

  const rows = Object.values(wb.transfers).reverse();
  const waiting = !connected && wb.state !== 'closed' && wb.state !== 'failed';

  return (
    <main className="mx-auto max-w-2xl px-5 pt-8 pb-12">
      <header className="flex items-center justify-between gap-4">
        <a href="/" className="text-lg font-bold tracking-tight">
          WebBeam
        </a>
        <span className="flex items-center gap-2 text-sm" role="status">
          <span className={`h-2.5 w-2.5 rounded-full ${dot}`} />
          {statusLabel(wb.state, wb.route)}
        </span>
      </header>

      <div className="mt-10">
        <LinkDiagram state={wb.state} route={wb.route} />
      </div>

      {wb.error && (
        <p role="alert" className="mt-6 text-sm text-bad">
          {wb.error}
        </p>
      )}
      {wb.state === 'closed' && <p className="mt-6 text-sm text-muted">{t.sessionClosed}</p>}

      {waiting && init.role === 'host' && <Invite link={link} code={init.code} />}
      {waiting && init.role === 'guest' && <p className="mt-10 text-muted">{t.joining}</p>}

      {connected && (
        <div className="mt-10 grid gap-8 md:grid-cols-2">
          <DropZone onFiles={wb.sendFiles} />
          <TextBox onSend={wb.sendText} />
        </div>
      )}

      {wb.texts.length > 0 && <TextList items={wb.texts} />}

      {rows.length > 0 && (
        <section className="mt-12">
          <div className="flex items-baseline justify-between gap-4 border-b border-line pb-2">
            <h2 className="font-semibold">{t.transfers}</h2>
            {sinkCapabilities().directoryPicker &&
              (dir ? (
                <span className="text-sm text-muted">
                  {t.dirChosen}{' '}
                  <button className="underline hover:text-ink" onClick={() => setDir(null)}>
                    {t.dirDrop}
                  </button>
                </span>
              ) : (
                <button
                  className="text-sm text-muted underline hover:text-ink"
                  onClick={() => void pickDirectory().then(setDir)}
                >
                  {t.pickDir}
                </button>
              ))}
          </div>
          <ul>
            {rows.map((p) => {
              const k = transferKey(p);
              return (
                <TransferRow
                  key={k}
                  p={p}
                  offer={wb.offers[k]}
                  received={wb.received[k]}
                  directory={dir}
                  onCancel={wb.cancel}
                />
              );
            })}
          </ul>
        </section>
      )}

      <footer className="mt-16 flex items-center justify-between gap-4 border-t border-line pt-4 text-sm text-muted">
        <span>{t.e2ee}</span>
        <button className="underline hover:text-ink" onClick={() => location.assign('/')}>
          {t.leave}
        </button>
      </footer>
    </main>
  );
}

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = async (what: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard indisponibil: textul e afisat si se poate selecta */
    }
  };
  return { copied, copy };
}

function Invite({ link, code }: { link: string; code: string | null }) {
  const [qr, setQr] = useState('');
  const { copied, copy } = useCopy();

  useEffect(() => {
    void QRCode.toDataURL(link, { margin: 1, width: 360, errorCorrectionLevel: 'M' }).then(setQr);
  }, [link]);

  return (
    <section className="mt-12 grid gap-8 border-t border-line pt-8 sm:grid-cols-[auto_1fr] sm:gap-10">
      <div className="h-44 w-44 shrink-0 overflow-hidden rounded-lg border border-line bg-white p-1.5">
        {qr && <img src={qr} width={168} height={168} alt="Cod QR pentru conectare" className="block h-full w-full" />}
      </div>

      <div className="min-w-0">
        <h2 className="text-xl font-bold tracking-tight">{t.inviteTitle}</h2>
        <p className="mt-1 text-muted">{t.inviteHint}</p>

        {code && (
          <div className="mt-5">
            <span className="code text-3xl select-all">{formatCode(code)}</span>
            <div className="mt-3">
              <button className="btn-quiet" onClick={() => void copy('code', formatCode(code))}>
                {copied === 'code' ? t.copied : t.copyCode}
              </button>
            </div>
          </div>
        )}

        <div className="mt-6 flex items-center gap-3">
          <code className="min-w-0 flex-1 truncate text-xs text-muted" title="Link de conectare">
            {link.replace(/#.*$/, '#…')}
          </code>
          <button className="btn-quiet shrink-0" onClick={() => void copy('link', link)}>
            {copied === 'link' ? t.copied : t.copyLink}
          </button>
        </div>
      </div>
    </section>
  );
}

function DropZone({ onFiles }: { onFiles: (f: File[]) => void }) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => input.current?.click()}
      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        onFiles([...e.dataTransfer.files]);
      }}
      className={`flex min-h-44 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-10 text-center transition-colors ${
        over ? 'border-ink bg-surface' : 'border-muted/50 hover:border-muted'
      }`}
    >
      <span className="text-lg font-semibold">{t.dropTitle}</span>
      <span className="mt-1 text-sm text-muted">{t.dropAlt}</span>
      <input
        ref={input}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          onFiles([...(e.target.files ?? [])]);
          e.target.value = '';
        }}
      />
    </div>
  );
}

function TextBox({ onSend }: { onSend: (text: string) => Promise<void> }) {
  const [value, setValue] = useState('');

  const send = async () => {
    const v = value;
    if (!v.trim()) return;
    setValue('');
    await onSend(v);
  };
  const pasteSend = async () => {
    try {
      const v = await navigator.clipboard.readText(); // cere gest + permisiune; de aceea e legat de un click
      if (v.trim()) await onSend(v);
    } catch {
      /* permisiune refuzata */
    }
  };

  return (
    <section>
      <label htmlFor="txt" className="font-semibold">
        {t.textLabel}
      </label>
      <textarea
        id="txt"
        rows={4}
        value={value}
        placeholder={t.textPlaceholder}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) void send();
        }}
        className="field mt-2 resize-y"
      />
      <div className="mt-2 flex gap-2">
        <button className="btn" onClick={() => void send()} disabled={!value.trim()}>
          {t.send}
        </button>
        <button className="btn-quiet" onClick={() => void pasteSend()}>
          {t.pasteSend}
        </button>
      </div>
    </section>
  );
}

function TextList({ items }: { items: TextItem[] }) {
  const { copied, copy } = useCopy();
  return (
    <section className="mt-12">
      <h2 className="border-b border-line pb-2 font-semibold">{t.received}</h2>
      <ul>
        {items.map((it) => (
          <li key={it.id} className="border-b border-line py-3 last:border-b-0">
            <p className="break-words whitespace-pre-wrap">{it.text}</p>
            <div className="mt-2 flex items-center justify-between gap-3">
              <span className="num text-sm text-muted">
                {it.from === 'me' ? '↑' : '↓'} {new Date(it.at).toLocaleTimeString()}
              </span>
              <button className="btn-quiet" onClick={() => void copy(`t${it.id}`, it.text)}>
                {copied === `t${it.id}` ? t.copied : t.copy}
              </button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
