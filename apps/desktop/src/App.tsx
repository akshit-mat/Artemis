import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";
import { register } from "@tauri-apps/plugin-global-shortcut";
import { useStore } from "./state/store";
import { connectWs, disconnectWs, sendChatMessage, cancelRun } from "./core/ws";
import { CardStream } from "./components/CardStream";
import { CoreVisual } from "./components/CoreVisual";
import { CommandPalette } from "./components/CommandPalette";
import { SettingsView } from "./components/SettingsView";

function App() {
  const { backendConfig, setBackendConfig, assistantState, lastError, setLastError, uiMode, sessions, activeSessionId, setActiveSessionId } = useStore();
  const [input, setInput] = useState("");
  const [activeTab, setActiveTab] = useState<"chat" | "settings">("chat");

  useEffect(() => {
    let isInitialized = false;
    let unlisten: (() => void) | null = null;

    async function init() {
      if (isInitialized) return;
      try {
        const handle = await invoke<{ port: number, token: string, origin: string }>("get_backend_handle");
        if (handle) {
          isInitialized = true;
          setBackendConfig({
            port: handle.port,
            tokenSet: !!handle.token,
            token: handle.token,
            origin: handle.origin,
          });
          connectWs(handle.port, handle.token);
        }
      } catch (e) {
        console.error("Failed to get backend handle", e);
      }
    }

    // 1. Subscribe to backend-ready before first attempt (catches cold start)
    listen("backend-ready", () => {
      init();
    }).then((unsub) => {
      unlisten = unsub;
    }).catch(console.error);

    // 2. Initial attempt (catches hot reloads where backend is already running)
    init();

    return () => {
      if (unlisten) unlisten();
      disconnectWs();
    };
  }, []);

  useEffect(() => {
    register('CommandOrControl+Alt+Space', async (shortcut) => {
      if (shortcut.state === 'Pressed') {
        const mode = useStore.getState().uiMode;
        const newMode = mode === 'full' ? 'hud' : 'full';
        useStore.getState().setUiMode(newMode);
        const win = getCurrentWindow();
        if (newMode === 'hud') {
          await win.setSize(new LogicalSize(420, 120));
          await win.setDecorations(false);
          await win.setAlwaysOnTop(true);
          await win.center();
        } else {
          await win.setSize(new LogicalSize(1024, 768));
          await win.setDecorations(true);
          await win.setAlwaysOnTop(false);
          await win.center();
        }
        await win.show();
        await win.setFocus();
      }
    }).catch(console.error);

    return () => {
      // In Tauri v2 we don't unregister all by default, but it's ok for this scope
    };
  }, []);

  // Phase 2: clear the error banner when the agent returns to IDLE
  // (i.e. the degraded run has concluded and a new run can start).
  useEffect(() => {
    if (assistantState?.state === 'IDLE' || assistantState?.state === 'idle') {
      setLastError(null);
    }
  }, [assistantState?.state]);

  // Fetch sessions when backend is ready
  useEffect(() => {
    if (!backendConfig || !backendConfig.tokenSet) return;
    const fetchSessions = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:${backendConfig.port}/v1/sessions`, {
          headers: { Authorization: `Bearer ${backendConfig.token}` }
        });
        if (res.ok) {
          const data = await res.json();
          useStore.getState().setSessions(data.sessions);
        }
      } catch (err) {
        console.error("Failed to fetch sessions:", err);
      }
    };
    fetchSessions();
  }, [backendConfig]);

  const handleSend = () => {
    if (!input.trim() || !activeSessionId) return;
    sendChatMessage(activeSessionId, input);
    setInput("");
  };

  const handleStop = () => {
    if (assistantState?.run_id) {
      cancelRun(assistantState.run_id);
    }
  };

  const isRunning = assistantState && !['IDLE', 'ERROR', 'OFFLINE'].includes(assistantState.state) && assistantState.run_id;

  if (uiMode === 'hud') {
    return (
      <div
        data-tauri-drag-region
        style={{
          display: 'flex',
          width: '100vw',
          height: '100vh',
          backgroundColor: '#1e1e1e',
          color: '#fff',
          alignItems: 'center',
          padding: '0 20px',
          boxSizing: 'border-box',
          border: '1px solid #333',
          borderRadius: '8px',
          overflow: 'hidden'
        }}
      >
        <div style={{ pointerEvents: 'none' }}>
          <CoreVisual />
        </div>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && input.trim()) {
              handleSend();
              // Auto-switch to full mode on query
              useStore.getState().setUiMode('full');
              const win = getCurrentWindow();
              win.setSize(new LogicalSize(1024, 768)).then(() => {
                win.setDecorations(true);
                win.setAlwaysOnTop(false);
                win.center();
              });
            }
          }}
          placeholder="Ask Artemis..."
          style={{
            flex: 1,
            marginLeft: '15px',
            padding: '10px',
            borderRadius: '4px',
            border: 'none',
            backgroundColor: '#2d2d2d',
            color: '#fff',
            outline: 'none',
            fontSize: '1rem'
          }}
          autoFocus
        />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', height: '100vh', width: '100vw', fontFamily: 'sans-serif', backgroundColor: '#1e1e1e', color: '#fff' }}>

      {/* SIDEBAR (Phase 3 navigation) */}
      <div style={{ width: '250px', backgroundColor: '#252526', borderRight: '1px solid #333', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '20px', fontWeight: 'bold', borderBottom: '1px solid #333' }}>Sessions</div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {sessions.map((session) => (
            <div
              key={session.id}
              onClick={() => setActiveSessionId(session.id)}
              style={{
                padding: '10px 20px',
                cursor: 'pointer',
                backgroundColor: activeSessionId === session.id ? '#37373d' : 'transparent',
                borderBottom: '1px solid #333',
                fontSize: '0.9rem',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis'
              }}
            >
              {session.title || session.id}
            </div>
          ))}
          {sessions.length === 0 && (
            <div style={{ padding: '10px 20px', color: '#888', fontSize: '0.9rem' }}>No sessions found</div>
          )}
        </div>
        <div style={{ padding: '20px', borderTop: '1px solid #333' }}>
          <button 
            onClick={() => setActiveTab(activeTab === 'chat' ? 'settings' : 'chat')}
            style={{ width: '100%', padding: '10px', backgroundColor: '#333', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
          >
            {activeTab === 'chat' ? '⚙️ Settings' : '💬 Chat'}
          </button>
        </div>
      </div>

      {/* STAGE */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', backgroundColor: '#1e1e1e', position: 'relative' }}>
        <div style={{ padding: '20px', borderBottom: '1px solid #333', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#d4d4d4' }}>ARTEMIS Phase 3: Dynamic Assistant State</h2>
            <div style={{ fontSize: '0.8rem', color: '#888', marginTop: '5px' }}>
              Port: {backendConfig?.port || '—'} | Origin: {backendConfig?.origin || '—'} | Auth: {backendConfig?.tokenSet ? 'Ready' : 'Pending'}
            </div>
          </div>
          <CoreVisual />
        </div>

        {/* Phase 2 error banner — shows agent.error code with dismiss */}
        {lastError && (
          <div
            id="agent-error-banner"
            role="alert"
            style={{
              padding: '12px 20px',
              backgroundColor: '#3a1a1a',
              borderBottom: '2px solid #c0392b',
              borderLeft: '4px solid #e74c3c',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span
                style={{
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  fontWeight: 'bold',
                  color: '#e74c3c',
                  padding: '2px 6px',
                  backgroundColor: '#4a1a1a',
                  borderRadius: '3px',
                  border: '1px solid #c0392b',
                }}
              >
                {lastError.code}
              </span>
              <span style={{ fontSize: '0.85rem', color: '#e8b4b4' }}>
                {lastError.message}
              </span>
            </div>
            <button
              id="dismiss-agent-error"
              onClick={() => setLastError(null)}
              style={{
                background: 'none',
                border: '1px solid #c0392b',
                color: '#e74c3c',
                borderRadius: '3px',
                padding: '2px 8px',
                cursor: 'pointer',
                fontSize: '0.75rem',
              }}
            >
              Dismiss
            </button>
          </div>
        )}

        {activeTab === 'settings' ? (
          <SettingsView />
        ) : (
          <>
            <CardStream />

            {/* INPUT */}
            <div style={{ padding: '20px', borderTop: '1px solid #333', display: 'flex', gap: '10px' }}>
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                placeholder="Type a message (Ctrl+K for commands)..."
                style={{ flex: 1, padding: '10px', borderRadius: '4px', border: '1px solid #555', backgroundColor: '#3c3c3c', color: '#fff' }}
              />
              <button
                onClick={handleSend}
                disabled={!input.trim()}
                style={{ padding: '10px 20px', borderRadius: '4px', border: 'none', backgroundColor: input.trim() ? '#007acc' : '#555', color: '#fff', cursor: input.trim() ? 'pointer' : 'not-allowed' }}
              >
                Send
              </button>
              {isRunning && (
                <button
                  id="stop-generation"
                  onClick={handleStop}
                  style={{ padding: '10px 20px', borderRadius: '4px', border: '1px solid #c0392b', backgroundColor: 'transparent', color: '#e74c3c', cursor: 'pointer' }}
                >
                  Stop
                </button>
              )}
            </div>
          </>
        )}
      </div>
      <CommandPalette />

      {/* CONTEXT PANEL */}
      <div style={{ width: '300px', backgroundColor: '#252526', borderLeft: '1px solid #333', padding: '20px', display: 'flex', flexDirection: 'column' }}>
        <h3 style={{ margin: '0 0 20px 0', fontSize: '1rem', color: '#d4d4d4' }}>Context</h3>

        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '0.8rem', color: '#888', textTransform: 'uppercase', marginBottom: '8px' }}>Assistant State</div>
          <div style={{ padding: '10px', backgroundColor: '#1e1e1e', borderRadius: '4px', border: '1px solid #333' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
              <span style={{ color: '#d4d4d4' }}>Status:</span>
              <span style={{ color: '#4caf50', fontWeight: 'bold' }}>{assistantState?.state || 'Unknown'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#d4d4d4' }}>Intensity:</span>
              <span style={{ color: '#ce9178' }}>{assistantState?.intensity ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}

export default App;
