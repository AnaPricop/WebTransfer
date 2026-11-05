import type { IncomingOffer, ReceivedFile, TransferProgress } from '../lib/webrtc';
import { formatEta, formatSpeed } from '../lib/webrtc';
import type { FsDirHandle } from '../lib/fileSink';
import { formatBytes, t } from '../strings';

interface Props {
  p: TransferProgress;
  offer?: IncomingOffer;
  received?: ReceivedFile;
  directory: FsDirHandle | null;
  onCancel: (id: number) => void;
}

const btn = 'btn-quiet';

export function TransferRow({ p, offer, received, directory, onCancel }: Props) {
  const pct = Math.round(p.fraction * 100);
  const active = p.state === 'active';

  let status: React.ReactNode = null;
  let actions: React.ReactNode = null;

  if (p.state === 'pending') {
    if (p.direction === 'receive' && offer) {
      actions = (
        <>
          {/* accept() trebuie apelat direct din click: deschide dialogul de salvare */}
          <button className={btn} onClick={() => void offer.accept(directory ? { directory } : undefined)}>
            {t.accept}
          </button>
          <button className={btn} onClick={() => offer.reject()}>
            {t.reject}
          </button>
        </>
      );
    } else {
      status = t.waitingConfirm;
      actions = (
        <button className={btn} onClick={() => onCancel(p.id)}>
          {t.cancel}
        </button>
      );
    }
  } else if (active) {
    status = `${pct}% · ${p.speedBps > 0 ? formatSpeed(p.speedBps) : '--'} · ${formatEta(p.etaSec)}`;
    actions = (
      <button className={btn} onClick={() => onCancel(p.id)}>
        {t.cancel}
      </button>
    );
  } else if (p.state === 'done') {
    if (p.direction === 'send') status = t.sent;
    else if (received?.result.saved) status = received.result.name ? `${t.savedDisk}: ${received.result.name}` : t.savedDisk;
    else if (received?.result.save) {
      status = null;
      actions = (
        <button className={btn} onClick={() => received.result.save?.()}>
          {t.save}
        </button>
      );
    } else status = t.savedDisk;
  } else if (p.state === 'rejected') status = t.rejected;
  else if (p.state === 'cancelled') status = t.cancelled;
  else if (p.state === 'error') status = `${t.failed}${p.error ? `: ${p.error}` : ''}`;

  return (
    <li className="border-b border-line py-3 last:border-b-0">
      <div className="flex items-baseline justify-between gap-3">
        <span className="min-w-0 truncate" title={p.name}>
          {p.direction === 'send' ? '↑' : '↓'} {p.name}
        </span>
        <span className="num shrink-0 text-sm text-muted">{formatBytes(p.size)}</span>
      </div>
      {active && (
        <div className="mt-2 h-1 overflow-hidden rounded-full bg-line">
          <div className="h-1 rounded-full bg-ink" style={{ width: `${pct}%` }} />
        </div>
      )}
      <div className="mt-2 flex items-center justify-between gap-3">
        <span className="num text-sm text-muted">{status}</span>
        <span className="flex gap-2">{actions}</span>
      </div>
    </li>
  );
}
