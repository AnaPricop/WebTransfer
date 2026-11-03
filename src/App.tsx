import { Home } from './components/Home';
import { Room } from './components/Room';

export function App() {
  const roomId = /^\/room\/([A-Za-z0-9_-]{8,32})\/?$/.exec(location.pathname)?.[1];
  return roomId ? <Room roomId={roomId} /> : <Home />;
}
