import { create } from 'zustand';
import type { components } from '../api/types';

type WSEnvelope = components["schemas"]["WSEnvelope"];
type AssistantStateData = components["schemas"]["AssistantStateData"];

interface AppState {
  wsStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  setWsStatus: (status: 'disconnected' | 'connecting' | 'connected' | 'error') => void;
  backendConfig: { port: number; tokenSet: boolean; origin: string } | null;
  setBackendConfig: (config: { port: number; tokenSet: boolean; origin: string }) => void;
  eventTimeline: WSEnvelope[];
  appendEvent: (event: WSEnvelope) => void;
  clearEvents: () => void;
  assistantState: AssistantStateData | null;
  setAssistantState: (state: AssistantStateData) => void;
}

export const useStore = create<AppState>((set) => ({
  wsStatus: 'disconnected',
  setWsStatus: (status) => set({ wsStatus: status }),
  backendConfig: null,
  setBackendConfig: (config) => set({ backendConfig: config }),
  eventTimeline: [],
  appendEvent: (event) => set((state) => ({ eventTimeline: [event, ...state.eventTimeline].slice(0, 100) })),
  clearEvents: () => set({ eventTimeline: [] }),
  assistantState: null,
  setAssistantState: (state) => set({ assistantState: state }),
}));
