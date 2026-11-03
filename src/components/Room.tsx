import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { buildRoomUrl, consumeRootKey, type Role } from '../lib/crypto';
import { pickDirectory, sinkCapabilities, type FsDirHandle } from '../lib/fileSink';
import { statusLabel, t } from '../strings';
import { transferKey, useWebBeam, type TextItem } from '../useWebBeam';
import { TransferRow } from './TransferRow';

const signalingUrl: string =
  import.meta.env.VITE_SIGNALING_URL || `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;

const primary =
  'rounded bg-neutral-100 px-3 py-1.5 text-xs font-medium text-neutral-900 hover:bg-white disabled:hover:bg-neutral-100';
const secondary = 'rounded border border-neutral-700 px-3 py-1.5 text-xs text-neutral-200 hover:border-neutral-500';

export function Room({ roomId }: { roomId: string }) {
  const [init] = useState(() => {
    const secure = typeof crypto !== 'undefined' && !!crypto.subtle;
    return {
      secure,
      key: secure ? consumeRootKey(roomId) : null,
      role: (sessionStorage.getItem(`webbeam:role:${roomId}`) === 'host' ? 'host' : 'guest') as Role,
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
      <main className="mx-auto max-w-xl px-5 py-16">
        <h1 className="text-xl font-semibold">WebBeam</h1>
        <p className="mt-4 text-sm text-red-400">{init.secure ? t.noKey : t.insecure}</p>
        <a href="/" className="mt-6 inline-block text-sm text-neutral-400 underline">
          {t.home}
        </a>
      </main>
    );
  }

  const dot =
    wb.state === 'connected'
      ? 'bg-emerald-500'
      : wb.state === 'failed'
        ? 'bg-red-500'
        : wb.state === 'closed' || wb.state === 'idle'
          ? 'bg-neutral-600'
          : 'bg-amber-500';

  const rows = Object.values(wb.transfers).reverse();

  return (
    <main className="mx-auto max-w-xl px-5 py-10">
      <header className="flex items-center justify-between">
        <a href="/" className="font-semibold">
          WebBeam
        </a>
        <span className="flex items-center gap-2 text-sm text-neutral-400">
          <span className={`h-2 w-2 rounded-full ${dot}`} />
          {statusLabel(wb.state, wb.route)}
        </span>
      </header>

      {wb.error && <p className="mt-4 text-sm text-red-400">{wb.error}</p>}

      {!connected && init.role === 'host' && <Invite link={link} />}
      {!connected && init.role === 'guest' && wb.state !== 'closed' && wb.state !== 'failed' && (
        <p className="mt-10 text-sm text-neutral-400">{t.joining}</p>
      )}
      {wb.state === 'closed' && <p className="mt-6 text-sm text-neutral-500">{t.sessionClosed}</p>}

      {connected && (
        <>
          <DropZone onFiles={wb.sendFiles} />
          <TextBox onSend={wb.sendText} />
        </>
      )}

      {wb.texts.length > 0 && <TextList items={wb.texts} />}

      {rows.length > 0 && (
        <section className="mt-10">
          <div className="flex items-baseline justify-between">
            <h2 className="text-sm text-neutral-300">{t.transfers}</h2>
            {sinkCapabilities().directoryPicker &&
              (dir ? (
                <span className="text-xs text-neutral-500">
                  {t.dirChosen}{' '}
                  <button className="underline hover:text-neutral-300" onClick={() => setDir(null)}>
                    {t.dirDrop}
                  </button>
                </span>
              ) : (
                <button
                  className="text-xs text-neutral-500 underline hover:text-neutral-300"
                  onClick={() => void pickDirectory().then(setDir)}
                >
                  {t.pickDir}
                </button>
              ))}
          </div>
          <ul className="mt-2">
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

      <footer className="mt-16 flex items-center justify-between text-xs text-neutral-600">
        <span>{t.e2ee}</span>
        <button className="underline hover:text-neutral-400" onClick={() => location.assign('/')}>
          {t.leave}
        </button>
      </footer>
    </main>
  );
}

function Invite({ link }: { link: string }) {
  const [qr, setQr] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void QRCode.toDataURL(link, { margin: 1, width: 224, errorCorrectionLevel: 'M' }).then(setQr);
  }, [link]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard indisponibil: linkul e afisat si se poate selecta */
    }
  };

  return (
    <section className="mt-10">
      <h2 className="text-sm text-neutral-300">{t.scanTitle}</h2>
      <div className="mt-4 inline-block rounded bg-white p-2">
        {qr ? <img src={qr} width={224} height={224} alt="QR" /> : <div style={{ width: 224, height: 224 }} />}
      </div>
      <p className="mt-6 text-xs text-neutral-500">{t.scanHint}</p>
      <div className="mt-2 flex items-start gap-3">
        <code className="min-w-0 flex-1 break-all text-xs text-neutral-400">{link}</code>
        <button className={secondary} onClick={copy}>
          {copied ? t.copied : t.copy}
        </button>
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
      onKeyDown={(e) => e.key === 'Enter' && input.current?.click()}
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
      className={`mt-10 cursor-pointer rounded border border-dashed px-4 py-10 text-center text-sm ${
        over ? 'border-neutral-400 text-neutral-200' : 'border-neutral-700 text-neutral-400'
      }`}
    >
      {t.dropTitle} <span className="text-neutral-500">{t.dropAlt}</span>
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
    <section className="mt-8">
      <label htmlFor="txt" className="text-sm text-neutral-300">
        {t.textLabel}
      </label>
      <textarea
        id="txt"
        rows={3}
        value={value}
        placeholder={t.textPlaceholder}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) void send();
        }}
        className="mt-2 w-full resize-y rounded border border-neutral-800 bg-transparent px-3 py-2 text-sm outline-none placeholder:text-neutral-600 focus:border-neutral-500"
      />
      <div className="mt-2 flex gap-2">
        <button className={primary} onClick={() => void send()} disabled={!value.trim()}>
          {t.send}
        </button>
        <button className={secondary} onClick={() => void pasteSend()}>
          {t.pasteSend}
        </button>
      </div>
    </section>
  );
}

function TextList({ items }: { items: TextItem[] }) {
  return (
    <section className="mt-10">
      <h2 className="text-sm text-neutral-300">{t.received}</h2>
      <ul className="mt-2">
        {items.map((it) => (
          <li key={it.id} className="border-b border-neutral-900 py-3 last:border-b-0">
            <p className="whitespace-pre-wrap break-words text-sm">{it.text}</p>
            <div className="mt-2 flex items-center justify-between">
              <span className="num text-xs text-neutral-500">
                {it.from === 'me' ? '↑' : '↓'} {new Date(it.at).toLocaleTimeString()}
              </span>
              <button className={secondary} onClick={() => void navigator.clipboard?.writeText(it.text)}>
                {t.copy}
              </button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
