import type { ConnectionState, RouteKind } from '../lib/webrtc';
import { t } from '../strings';

type Tone = 'idle' | 'waiting' | 'seeking' | 'linked' | 'broken';

function toneOf(state: ConnectionState): Tone {
  switch (state) {
    case 'connected':
      return 'linked';
    case 'negotiating':
    case 'reconnecting':
      return 'seeking';
    case 'waiting-for-peer':
      return 'waiting';
    case 'failed':
    case 'closed':
      return 'broken';
    default:
      return 'idle';
  }
}

const stroke = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.75,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
} as const;

function Laptop() {
  return (
    <svg viewBox="0 0 64 48" width="64" height="48" aria-hidden="true" {...stroke}>
      <rect x="10" y="5" width="44" height="29" rx="3" />
      <path d="M4 41h56l-4-7H8z" />
    </svg>
  );
}

function Phone() {
  return (
    <svg viewBox="0 0 64 48" width="64" height="48" aria-hidden="true" {...stroke}>
      <rect x="22" y="3" width="20" height="42" rx="4" />
      <path d="M29 39h6" />
    </svg>
  );
}

/** Schita celor doua dispozitive; linia dintre ele arata starea conexiunii. */
export function LinkDiagram({ state, route }: { state: ConnectionState; route: RouteKind }) {
  const tone = toneOf(state);
  // pe ecran mic, "acest dispozitiv" e probabil telefonul
  const narrow = typeof window !== 'undefined' && window.matchMedia('(max-width: 640px)').matches;
  const Here = narrow ? Phone : Laptop;
  const There = narrow ? Laptop : Phone;
  const linked = tone === 'linked';
  const faint = tone === 'idle' || tone === 'waiting';
  const label = route === 'direct' ? t.routeDirect : route === 'relay' ? t.routeRelay : t.routeUnknown;

  return (
    <div className="grid grid-cols-[auto_1fr_auto] items-start gap-x-3 sm:gap-x-5">
      <figure className="flex flex-col items-center gap-1.5">
        <Here />
        <figcaption className="text-sm text-muted">{t.thisDevice}</figcaption>
      </figure>

      <div className={`mt-6 text-center ${tone === 'broken' ? 'text-bad' : linked ? 'text-ink' : 'text-muted'}`}>
        <svg className="beam block" data-tone={tone} width="100%" height="10" aria-hidden="true">
          <line x1="3" y1="5" x2="99%" y2="5" />
        </svg>
        {linked && <span className="mt-1.5 inline-block text-sm font-medium text-ok">{label}</span>}
      </div>

      <figure className={`flex flex-col items-center gap-1.5 transition-opacity ${faint ? 'opacity-45' : ''}`}>
        <There />
        <figcaption className="text-sm text-muted">{t.otherDevice}</figcaption>
      </figure>
    </div>
  );
}
