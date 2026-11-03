// Toate textele din interfata, intr-un singur loc (usor de tradus sau de pus cu diacritice).
import type { ConnectionState, RouteKind } from './lib/webrtc';

export const t = {
  tagline: 'Trimite fisiere si text direct intre dispozitive. Criptat cap la cap, nimic nu ramane pe server.',
  start: 'Porneste o sesiune',
  steps: [
    'Porneste o sesiune pe calculator.',
    'Scaneaza codul QR cu telefonul (sau deschide linkul).',
    'Alege fisiere sau scrie un text. Merge in ambele sensuri.',
  ],
  keyNote: 'Cheia de criptare sta in link, dupa #, si nu ajunge niciodata la un server.',
  insecure: 'Aplicatia are nevoie de HTTPS (sau localhost) ca sa foloseasca criptarea din browser.',
  noKey: 'Linkul nu contine cheia de criptare. Cere un cod QR nou de la celalalt dispozitiv.',
  home: 'Pagina principala',
  scanTitle: 'Scaneaza pentru a te conecta',
  scanHint: 'Sau deschide linkul pe celalalt dispozitiv:',
  copy: 'Copiaza',
  copied: 'Copiat',
  joining: 'Se conecteaza la sesiune...',
  dropTitle: 'Trage fisiere aici',
  dropAlt: 'sau alege din dispozitiv',
  textLabel: 'Text',
  textPlaceholder: 'Scrie sau lipeste un text',
  send: 'Trimite',
  pasteSend: 'Lipeste din clipboard si trimite',
  received: 'Mesaje',
  noTransfers: 'Niciun transfer.',
  transfers: 'Transferuri',
  accept: 'Accepta',
  reject: 'Refuza',
  cancel: 'Anuleaza',
  save: 'Salveaza',
  savedDisk: 'Salvat pe disc',
  sent: 'Trimis',
  waitingConfirm: 'Se asteapta confirmarea',
  rejected: 'Refuzat',
  cancelled: 'Anulat',
  failed: 'Eroare',
  pickDir: 'Salveaza automat intr-un folder',
  dirChosen: 'Primesti automat in folderul ales',
  dirDrop: 'Renunta',
  leave: 'Inchide sesiunea',
  sessionClosed: 'Conexiune inchisa. Daca celalalt dispozitiv revine in aceeasi sesiune, se reconecteaza singur.',
  e2ee: 'Criptat cap la cap',
};

export function statusLabel(state: ConnectionState, route: RouteKind): string {
  switch (state) {
    case 'idle':
      return 'Inactiv';
    case 'connecting-signaling':
      return 'Se conecteaza la server';
    case 'waiting-for-peer':
      return 'Se asteapta celalalt dispozitiv';
    case 'negotiating':
      return 'Se stabileste conexiunea';
    case 'connected':
      return route === 'relay' ? 'Conectat prin relay' : 'Conectat direct';
    case 'reconnecting':
      return 'Se reconecteaza';
    case 'failed':
      return 'Conexiune esuata';
    case 'closed':
      return 'Conexiune inchisa';
  }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}
