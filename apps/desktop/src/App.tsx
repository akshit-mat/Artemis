import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useStore } from "./state/store";
import { connectWs, disconnectWs, sendTestMessage } from "./core/ws";

function App() {
  const { wsStatus, backendConfig, setBackendConfig, eventTimeline, assistantState } = useStore();
  const [input, setInput] = useState("");

  useEffect(() => {
    async function init() {
      try {
        const handle = await invoke<{ port: number, token: string, origin: string }>("get_backend_handle");
        if (handle) {
          setBackendConfig({
            port: handle.port,
            tokenSet: !!handle.token,
            origin: handle.origin,
          });
          connectWs(handle.port, handle.token);
        }
      } catch (e) {
        console.error("Failed to get backend handle", e);
      }
    }
    init();

    return () => {
      disconnectWs();
    };
  }, []);

  return (
    <div style={{ display: 'flex', height: '100vh', width: '100vw', fontFamily: 'sans-serif', backgroundColor: '#1e1e1e', color: '#fff' }}>
      
      {/* RAIL */}
      <div style={{ width: '60px', backgroundColor: '#252526', borderRight: '1px solid #333', display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '10px 0' }}>
        <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: '#007acc', marginBottom: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold' }}>
          A
        </div>
        <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: wsStatus === 'connected' ? '#4caf50' : wsStatus === 'connecting' ? '#ff9800' : '#f44336', marginTop: 'auto' }} title={`WS Status: ${wsStatus}`} />
      </div>

      {/* STAGE */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', backgroundColor: '#1e1e1e', position: 'relative' }}>
        <div style={{ padding: '20px', borderBottom: '1px solid #333' }}>
          <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#d4d4d4' }}>ARTEMIS Phase 1: Secure Walking Skeleton</h2>
          <div style={{ fontSize: '0.8rem', color: '#888', marginTop: '5px' }}>
            Port: {backendConfig?.port || '—'} | Origin: {backendConfig?.origin || '—'} | Auth: {backendConfig?.tokenSet ? 'Ready' : 'Pending'}
          </div>
        </div>

        <div style={{ flex: 1, padding: '20px', overflowY: 'auto', display: 'flex', flexDirection: 'column-reverse' }}>
          {eventTimeline.map((ev, i) => (
            <div key={i} style={{ marginBottom: '10px', padding: '10px', backgroundColor: '#2d2d2d', borderRadius: '4px', borderLeft: '4px solid #007acc' }}>
              <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '4px', display: 'flex', justifyContent: 'space-between' }}>
                <span>SEQ: {ev.seq || '-'}</span>
                <span>{new Date(ev.ts).toLocaleTimeString()}</span>
              </div>
              <div style={{ fontWeight: 'bold', color: '#d4d4d4', marginBottom: '4px' }}>{ev.type}</div>
              <pre style={{ margin: 0, fontSize: '0.8rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#ce9178' }}>
                {JSON.stringify(ev.data, null, 2)}
              </pre>
            </div>
          ))}
          {eventTimeline.length === 0 && (
            <div style={{ color: '#888', textAlign: 'center', marginTop: '20px' }}>No events yet. Waiting for backend...</div>
          )}
        </div>

        <div style={{ padding: '20px', borderTop: '1px solid #333', backgroundColor: '#252526' }}>
          <div style={{ display: 'flex' }}>
            <input 
              type="text" 
              value={input} 
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { sendTestMessage(input); setInput(''); } }}
              placeholder="Test chat.send event..."
              style={{ flex: 1, padding: '10px', backgroundColor: '#3c3c3c', color: '#fff', border: '1px solid #555', borderRadius: '4px 0 0 4px', outline: 'none' }}
            />
            <button 
              onClick={() => { sendTestMessage(input); setInput(''); }}
              disabled={wsStatus !== 'connected' || !input.trim()}
              style={{ padding: '10px 20px', backgroundColor: '#007acc', color: '#fff', border: 'none', borderRadius: '0 4px 4px 0', cursor: wsStatus === 'connected' ? 'pointer' : 'not-allowed', opacity: wsStatus === 'connected' ? 1 : 0.5 }}
            >
              Send
            </button>
          </div>
        </div>
      </div>

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
