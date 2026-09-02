import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useStore } from "./state/store";
import { connectWs, disconnectWs, sendTestMessage } from "./core/ws";

function App() {
  const { wsStatus, lastMessage, backendConfig, setBackendConfig } = useStore();
  const [input, setInput] = useState("");

  useEffect(() => {
    async function init() {
      try {
        const handle: any = await invoke("get_backend_handle");
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
    <div style={{ padding: "20px", fontFamily: "sans-serif" }}>
      <h2>ARTEMIS Phase 1: Secure Walking Skeleton</h2>
      
      <div style={{ marginBottom: "20px", padding: "10px", border: "1px solid #ccc" }}>
        <h3>Backend Status</h3>
        <p>Port: {backendConfig?.port || "Unknown"}</p>
        <p>Origin: {backendConfig?.origin || "Unknown"}</p>
        <p>Token: {backendConfig?.tokenSet ? "Available (Hidden)" : "Missing"}</p>
      </div>

      <div style={{ marginBottom: "20px", padding: "10px", border: "1px solid #ccc" }}>
        <h3>WebSocket Status</h3>
        <p>State: <strong>{wsStatus}</strong></p>
        <p>Last Message: {lastMessage}</p>
      </div>

      <div>
        <input 
          type="text" 
          value={input} 
          onChange={(e) => setInput(e.target.value)} 
          placeholder="Test message..."
          style={{ marginRight: "10px", padding: "5px" }}
        />
        <button 
          onClick={() => sendTestMessage(input)}
          disabled={wsStatus !== 'connected'}
          style={{ padding: "5px 10px" }}
        >
          Send
        </button>
      </div>
    </div>
  );
}

export default App;
