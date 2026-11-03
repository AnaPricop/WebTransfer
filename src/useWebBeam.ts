import { useCallback, useEffect, useRef, useState } from 'react';
import type { Bytes, Role } from './lib/crypto';
import type { FsDirHandle } from './lib/fileSink';
import {
  WebBeamPeer,
  type ConnectionState,
  type IncomingOffer,
  type ReceivedFile,
  type RouteKind,
  type TransferProgress,
} from './lib/webrtc';

export interface TextItem {
  id: number;
  text: string;
  at: number;
  from: 'me' | 'peer';
}

interface Config {
  roomId: string;
  rootKey: Bytes | null;
  role: Role;
  signalingUrl: string;
  /** Daca e setat, fisierele primite se accepta automat in acest director (fara dialog per fisier). */
  directory: FsDirHandle | null;
}

export const transferKey = (p: { direction: 'send' | 'receive'; id: number }) => `${p.direction}:${p.id}`;

export function useWebBeam({ roomId, rootKey, role, signalingUrl, directory }: Config) {
  const peerRef = useRef<WebBeamPeer | null>(null);
  const dirRef = useRef<FsDirHandle | null>(directory);
  dirRef.current = directory;
  const textId = useRef(0);

  const [state, setState] = useState<ConnectionState>('idle');
  const [route, setRoute] = useState<RouteKind>('unknown');
  const [error, setError] = useState<string | null>(null);
  const [transfers, setTransfers] = useState<Record<string, TransferProgress>>({});
  const [offers, setOffers] = useState<Record<string, IncomingOffer>>({});
  const [received, setReceived] = useState<Record<string, ReceivedFile>>({});
  const [texts, setTexts] = useState<TextItem[]>([]);

  useEffect(() => {
    if (!rootKey) return;
    const peer = new WebBeamPeer({ signalingUrl, roomId, rootKey, role });
    peerRef.current = peer;

    const unsubscribe = [
      peer.on('state', (s) => {
        setState(s);
        if (s === 'connected') setError(null);
      }),
      peer.on('route', setRoute),
      peer.on('error', (e) => setError(e.message)),
      peer.on('text', (text) =>
        setTexts((l) => [{ id: ++textId.current, text, at: Date.now(), from: 'peer' }, ...l]),
      ),
      peer.on('progress', (p) => setTransfers((m) => ({ ...m, [transferKey(p)]: p }))),
      peer.on('incomingFile', (offer) => {
        setOffers((m) => ({ ...m, [`receive:${offer.id}`]: offer }));
        if (dirRef.current) void offer.accept({ directory: dirRef.current });
      }),
      peer.on('fileReceived', (f) => setReceived((m) => ({ ...m, [`receive:${f.id}`]: f }))),
    ];

    peer.start().catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
    return () => {
      unsubscribe.forEach((off) => off());
      peer.close();
      peerRef.current = null;
    };
  }, [roomId, rootKey, role, signalingUrl]);

  const sendFiles = useCallback((files: File[]) => {
    if (!files.length) return;
    try {
      peerRef.current?.sendFiles(files);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const sendText = useCallback(async (text: string) => {
    if (!text.trim()) return;
    try {
      const kind = await peerRef.current?.sendText(text);
      if (kind === 'text') setTexts((l) => [{ id: ++textId.current, text, at: Date.now(), from: 'me' }, ...l]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const cancel = useCallback((id: number) => peerRef.current?.cancel(id), []);

  return { state, route, error, transfers, offers, received, texts, sendFiles, sendText, cancel };
}
