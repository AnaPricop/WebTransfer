import { buildRoomUrl, generateRoomId, generateRootKey } from '../lib/crypto';
import { t } from '../strings';

export function Home() {
  const secure = typeof crypto !== 'undefined' && !!crypto.subtle;

  const start = () => {
    const id = generateRoomId();
    sessionStorage.setItem(`webbeam:role:${id}`, 'host');
    location.assign(buildRoomUrl(location.origin, id, generateRootKey()));
  };

  return (
    <main className="mx-auto max-w-xl px-5 py-16">
      <h1 className="text-xl font-semibold">WebBeam</h1>
      <p className="mt-3 text-neutral-400">{t.tagline}</p>

      {secure ? (
        <button
          onClick={start}
          className="mt-8 rounded bg-neutral-100 px-4 py-2 text-sm font-medium text-neutral-900 hover:bg-white"
        >
          {t.start}
        </button>
      ) : (
        <p className="mt-8 text-sm text-red-400">{t.insecure}</p>
      )}

      <ol className="mt-12 list-inside list-decimal space-y-2 text-sm text-neutral-500">
        {t.steps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      <p className="mt-12 text-xs text-neutral-600">{t.keyNote}</p>
    </main>
  );
}
