// Toate textele din interfata, intr-un singur loc (usor de tradus sau de pus cu diacritice).
import type { ConnectionState, RouteKind } from './lib/webrtc';

export const t = {
  headline: 'Fisiere si text, de pe un dispozitiv pe altul.',
  tagline: 'Direct intre dispozitive, criptat cap la cap. Nimic nu se salveaza pe server.',
  start: 'Porneste o sesiune',
  starting: 'Se pregateste...',
  codeLabel: 'Ai un cod?',
  codePlaceholder: 'ABCDE-FGHJK',
  codeJoin: 'Conecteaza',
  codeChecking: 'Se verifica...',
  codeInvalid: 'Codul are 10 caractere (litere si cifre).',
  howTitle: 'Cum merge',
  how: 'Porneste o sesiune pe un dispozitiv. Pe celalalt scaneaza codul QR sau scrie codul de conectare. Apoi alege fisiere sau scrie un text, in ambele sensuri.',
  keyNote: 'Cheia de criptare e in link, dupa #, si nu ajunge la niciun server.',
  insecure: 'Aplicatia are nevoie de HTTPS (sau localhost) ca sa foloseasca criptarea din browser.',
  noKey: 'Linkul nu contine cheia de criptare. Cere un cod QR sau un cod nou de la celalalt dispozitiv.',
  home: 'Pagina principala',
  inviteTitle: 'Conecteaza celalalt dispozitiv',
  inviteHint: 'Scaneaza codul QR sau scrie acest cod pe celalalt dispozitiv.',
  copyCode: 'Copiaza codul',
  copyLink: 'Copiaza linkul',
  copy: 'Copiaza',
  copied: 'Copiat',
  joining: 'Se conecteaza la sesiune...',
  thisDevice: 'Acest dispozitiv',
  otherDevice: 'Celalalt dispozitiv',
  routeDirect: 'Direct',
  routeRelay: 'Prin relay',
  routeUnknown: 'Conectat',
  dropTitle: 'Trage fisiere aici',
  dropAlt: 'sau alege din dispozitiv',
  textLabel: 'Text',
  textPlaceholder: 'Scrie sau lipeste un text',
  send: 'Trimite',
  pasteSend: 'Lipeste si trimite',
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
