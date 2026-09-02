import { create } from 'zustand';

interface AppState {
  wsStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  setWsStatus: (status: 'disconnected' | 'connecting' | 'connected' | 'error') => void;
  lastMessage: string | null;
  setLastMessage: (msg: string) => void;
  backendConfig: { port: number; tokenSet: boolean; origin: string } | null;
  setBackendConfig: (config: { port: number; tokenSet: boolean; origin: string }) => void;
}

export const useStore = create<AppState>((set) => ({
  wsStatus: 'disconnected',
  setWsStatus: (status) => set({ wsStatus: status }),
  lastMessage: null,
  setLastMessage: (msg) => set({ lastMessage: msg }),
  backendConfig: null,
  setBackendConfig: (config) => set({ backendConfig: config }),
}));
