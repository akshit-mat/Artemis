import { create } from 'zustand';
import type { components } from '../api/types';

type WSEnvelope = components["schemas"]["WSEnvelope"];
type AssistantStateData = components["schemas"]["AssistantStateData"];

interface AgentError {
  code: string;
  message: string;
  recoverable: boolean;
  correlation_id: string | null;
}

interface BufferedDelta {
  run_id: string;
  channel: string;
  text: string;
}

export type CardType = 'message' | 'tool' | 'approval' | 'denial' | 'task' | 'error';

export interface Card {
  id: string; // msg_id or run_id
  type: CardType;
  role?: string;
  content: string;
  reasoning?: string;
  finish_reason?: string;
}

interface AppState {
  wsStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  setWsStatus: (status: 'disconnected' | 'connecting' | 'connected' | 'error') => void;
  backendConfig: { port: number; tokenSet: boolean; token?: string; origin: string } | null;
  setBackendConfig: (config: { port: number; tokenSet: boolean; token?: string; origin: string }) => void;
  eventTimeline: WSEnvelope[];
  appendEvent: (event: WSEnvelope) => void;
  clearEvents: () => void;
  assistantState: AssistantStateData | null;
  setAssistantState: (state: AssistantStateData) => void;
  /** The most recent agent.error payload. Drives the Phase 2 error banner. */
  lastError: AgentError | null;
  setLastError: (err: AgentError | null) => void;

  // Phase 3 heterogeneous card stream
  cards: Record<string, Card>;
  cardIds: string[];
  addCard: (card: Card) => void;
  applyDeltas: (deltas: BufferedDelta[]) => void;
  updateCard: (id: string, updates: Partial<Card>) => void;
  uiMode: 'full' | 'hud';
  setUiMode: (mode: 'full' | 'hud') => void;
  settings: { reducedMotion: boolean };
  setSettings: (settings: { reducedMotion: boolean }) => void;
  sessions: any[];
  setSessions: (sessions: any[]) => void;
  activeSessionId: string | null;
  setActiveSessionId: (id: string | null) => void;
  isBattery: boolean;
  setIsBattery: (isBattery: boolean) => void;
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
  lastError: null,
  setLastError: (err) => set({ lastError: err }),

  cards: {},
  cardIds: [],
  addCard: (card) => set((state) => {
    if (state.cards[card.id]) return state; // Deduplicate
    return {
      cards: { ...state.cards, [card.id]: card },
      cardIds: [...state.cardIds, card.id]
    };
  }),
  applyDeltas: (deltas) => set((state) => {
    const nextCards = { ...state.cards };
    let changed = false;
    for (const d of deltas) {
      let cardId = d.run_id; // By default we append to the run's active card
      let c = nextCards[cardId];
      if (!c) {
        c = { id: cardId, type: 'message', role: 'assistant', content: '', reasoning: '' };
        nextCards[cardId] = c;
        // Wait, we can't mutate cardIds safely without copying, but we can do it if changed is true
        if (!state.cards[cardId]) {
            // Need to handle adding new card in applyDeltas if it doesn't exist
            // but we'll do it cleanly below
        }
      }

      // We MUST copy the card object to trigger React re-renders
      c = { ...c };
      if (d.channel === 'reasoning') {
        c.reasoning = (c.reasoning || '') + d.text;
      } else {
        c.content = (c.content || '') + d.text;
      }
      nextCards[cardId] = c;
      changed = true;
    }

    if (!changed) return state;

    // Check if we need to append new ids
    const newIds = Object.keys(nextCards).filter(id => !state.cards[id]);
    const nextCardIds = newIds.length > 0 ? [...state.cardIds, ...newIds] : state.cardIds;

    return { cards: nextCards, cardIds: nextCardIds };
  }),
  updateCard: (id, updates) => set((state) => {
    if (!state.cards[id]) return state;
    return {
      cards: { ...state.cards, [id]: { ...state.cards[id], ...updates } }
    };
  }),
  uiMode: 'full',
  setUiMode: (mode) => set({ uiMode: mode }),
  settings: { reducedMotion: false },
  setSettings: (settings) => set({ settings }),
  sessions: [],
  setSessions: (sessions) => set({ sessions }),
  activeSessionId: 's_test', // Start with default
  setActiveSessionId: (id) => set({ activeSessionId: id, cards: {}, cardIds: [] }),
  isBattery: false,
  setIsBattery: (isBattery) => set({ isBattery }),
}));
