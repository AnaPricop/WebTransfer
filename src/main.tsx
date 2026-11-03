import { createRoot } from 'react-dom/client';
import { App } from './App';
import { purgeStaleReceiveData } from './lib/fileSink';
import './index.css';

// Date ramase in IndexedDB dintr-un transfer intrerupt (fallback Safari/iOS).
void purgeStaleReceiveData();

createRoot(document.getElementById('root')!).render(<App />);
