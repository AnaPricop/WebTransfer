import { useState } from 'react';
import {
  CODE_LENGTH,
  buildRoomUrl,
  deriveFromCode,
  formatCode,
  generateCode,
  normalizeCode,
} from '../lib/crypto';
import { t } from '../strings';
import { LinkDiagram } from './LinkDiagram';

export function Home() {
  const secure = typeof crypto !== 'undefined' && !!crypto.subtle;
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState<'start' | 'join' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const open = async (c: string, role: 'host' | 'guest') => {
    const { roomId, rootKey } = await deriveFromCode(c);
    if (role === 'host') {
      sessionStorage.setItem(`webbeam:role:${roomId}`, 'host');
      sessionStorage.setItem(`webbeam:code:${roomId}`, normalizeCode(c));
    }
    location.assign(buildRoomUrl(location.origin, roomId, rootKey));
  };

  const start = async () => {
    setBusy('start');
    setError(null);
    try {
      await open(generateCode(), 'host');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(null);
    }
  };

  const join = async (e: React.FormEvent) => {
    e.preventDefault();
    if (normalizeCode(code).length !== CODE_LENGTH) {
      setError(t.codeInvalid);
      return;
    }
    setBusy('join');
    setError(null);
    try {
      await open(code, 'guest');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(null);
    }
  };

  return (
    <main className="mx-auto max-w-2xl px-5 pt-8 pb-16 sm:pt-12">
      <span className="text-lg font-bold tracking-tight">WebBeam</span>

      <h1 className="mt-14 max-w-[16ch] text-[clamp(2.25rem,7vw,3.5rem)] leading-[1.04] font-bold tracking-tight">
        {t.headline}
      </h1>
      <p className="mt-4 max-w-[44ch] text-lg text-muted">{t.tagline}</p>

      <div className="mt-12">
        <LinkDiagram state="waiting-for-peer" route="unknown" />
      </div>

      {secure ? (
        <div className="mt-12 flex flex-col gap-8 sm:flex-row sm:items-end sm:gap-10">
          <button className="btn" onClick={() => void start()} disabled={busy !== null}>
            {busy === 'start' ? t.starting : t.start}
          </button>

          <form onSubmit={(e) => void join(e)} className="sm:flex-1">
            <label htmlFor="code" className="block text-sm text-muted">
              {t.codeLabel}
            </label>
            <div className="mt-1.5 flex gap-2">
              <input
                id="code"
                className="field min-w-0 font-mono tracking-wider"
                value={code}
                onChange={(e) => {
                  setCode(formatCode(e.target.value));
                  setError(null);
                }}
                placeholder={t.codePlaceholder}
                autoComplete="off"
                autoCapitalize="characters"
                autoCorrect="off"
                spellCheck={false}
                inputMode="text"
                maxLength={CODE_LENGTH + 1}
              />
              <button type="submit" className="btn-quiet shrink-0 px-4" disabled={busy !== null}>
                {busy === 'join' ? t.codeChecking : t.codeJoin}
              </button>
            </div>
          </form>
        </div>
      ) : (
        <p className="mt-12 text-bad">{t.insecure}</p>
      )}
      {error && (
        <p role="alert" className="mt-4 text-sm text-bad">
          {error}
        </p>
      )}

      <section className="mt-16 max-w-[56ch] border-t border-line pt-6">
        <h2 className="font-semibold">{t.howTitle}</h2>
        <p className="mt-2 text-muted">{t.how}</p>
        <p className="mt-4 text-sm text-muted">{t.keyNote}</p>
      </section>
    </main>
  );
}
