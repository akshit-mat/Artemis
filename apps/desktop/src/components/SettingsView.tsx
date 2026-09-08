import { useEffect, useState } from 'react';
import { useStore } from '../state/store';

export interface Grant {
  id: string;
  action_text: string;
  tool_name: string;
  targets: string[];
  scope_type: string;
}

export function SettingsView() {
  const { backendConfig } = useStore();
  const [grants, setGrants] = useState<Grant[]>([]);
  const [roots, setRoots] = useState<string[]>([]);
  const [newRoot, setNewRoot] = useState('');
  const [confirmRisk, setConfirmRisk] = useState(false);

  const fetchGrants = async () => {
    if (!backendConfig) return;
    try {
      const res = await fetch(`http://127.0.0.1:${backendConfig.port}/v1/grants`, {
        headers: { Authorization: `Bearer ${backendConfig.token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setGrants(data.grants);
      }
    } catch (e) {
      console.error('Failed to fetch grants', e);
    }
  };

  const fetchRoots = async () => {
    if (!backendConfig) return;
    try {
      const res = await fetch(`http://127.0.0.1:${backendConfig.port}/v1/settings/fs`, {
        headers: { Authorization: `Bearer ${backendConfig.token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setRoots(data.allow_roots);
      }
    } catch (e) {
      console.error('Failed to fetch roots', e);
    }
  };

  useEffect(() => {
    fetchGrants();
    fetchRoots();
  }, [backendConfig]);

  const revokeGrant = async (id: string) => {
    if (!backendConfig) return;
    try {
      const res = await fetch(`http://127.0.0.1:${backendConfig.port}/v1/grants/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${backendConfig.token}` }
      });
      if (res.ok) fetchGrants();
    } catch (e) {
      console.error('Failed to revoke grant', e);
    }
  };

  const addRoot = async () => {
    if (!backendConfig || !newRoot) return;
    try {
      const res = await fetch(`http://127.0.0.1:${backendConfig.port}/v1/settings/fs/roots`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${backendConfig.token}`
        },
        body: JSON.stringify({ root: newRoot, confirm_risk: confirmRisk })
      });
      if (res.ok) {
        setNewRoot('');
        setConfirmRisk(false);
        fetchRoots();
      } else {
        const data = await res.json();
        alert(`Failed: ${data.error?.message || 'Unknown error'}`);
      }
    } catch (e) {
      console.error('Failed to add root', e);
    }
  };

  const removeRoot = async (root: string) => {
    if (!backendConfig) return;
    try {
      const res = await fetch(`http://127.0.0.1:${backendConfig.port}/v1/settings/fs/roots`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${backendConfig.token}`
        },
        body: JSON.stringify({ root })
      });
      if (res.ok) fetchRoots();
    } catch (e) {
      console.error('Failed to remove root', e);
    }
  };

  return (
    <div style={{ padding: '20px', overflowY: 'auto', flex: 1, backgroundColor: '#1e1e1e', color: '#fff', fontFamily: 'sans-serif' }}>
      <h2 style={{ color: '#d4d4d4' }}>Permissions (Grants)</h2>
      {grants.length === 0 ? <p style={{ color: '#888' }}>No active grants.</p> : (
        <ul style={{ listStyleType: 'none', padding: 0 }}>
          {grants.map(g => (
            <li key={g.id} style={{ marginBottom: '10px', padding: '10px', backgroundColor: '#333', borderRadius: '4px', fontSize: '0.9rem' }}>
              <div><strong style={{ color: '#9cdcfe' }}>Action:</strong> {g.action_text}</div>
              <div><strong style={{ color: '#9cdcfe' }}>Tool:</strong> {g.tool_name}</div>
              {g.targets && g.targets.length > 0 && <div><strong style={{ color: '#9cdcfe' }}>Targets:</strong> {g.targets.join(', ')}</div>}
              <div><strong style={{ color: '#9cdcfe' }}>Scope:</strong> {g.scope_type}</div>
              <button onClick={() => revokeGrant(g.id)} style={{ marginTop: '10px', padding: '5px 10px', backgroundColor: '#d32f2f', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Revoke</button>
            </li>
          ))}
        </ul>
      )}

      <h2 style={{ marginTop: '40px', color: '#d4d4d4' }}>Allowed Filesystem Roots</h2>
      {roots.length === 0 ? <p style={{ color: '#888' }}>No roots allowed yet.</p> : (
        <ul style={{ listStyleType: 'none', padding: 0 }}>
          {roots.map(r => (
            <li key={r} style={{ marginBottom: '10px', display: 'flex', gap: '10px', alignItems: 'center' }}>
              <span style={{ fontFamily: 'monospace', padding: '5px 10px', backgroundColor: '#333', borderRadius: '4px', color: '#ce9178', flex: 1 }}>{r}</span>
              <button onClick={() => removeRoot(r)} style={{ padding: '5px 10px', backgroundColor: '#d32f2f', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Remove</button>
            </li>
          ))}
        </ul>
      )}
      <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '10px', maxWidth: '400px', backgroundColor: '#252526', padding: '15px', borderRadius: '6px' }}>
        <input 
          type="text" 
          value={newRoot} 
          onChange={e => setNewRoot(e.target.value)} 
          placeholder="New Root Path (e.g. C:\Projects)" 
          style={{ padding: '8px', borderRadius: '4px', border: '1px solid #555', backgroundColor: '#1e1e1e', color: '#fff' }}
        />
        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem', color: '#ccc' }}>
          <input type="checkbox" checked={confirmRisk} onChange={e => setConfirmRisk(e.target.checked)} />
          Confirm Risk (Required to add roots)
        </label>
        <button onClick={addRoot} disabled={!confirmRisk || !newRoot.trim()} style={{ padding: '8px', backgroundColor: (confirmRisk && newRoot.trim()) ? '#388e3c' : '#555', color: '#fff', border: 'none', borderRadius: '4px', cursor: (confirmRisk && newRoot.trim()) ? 'pointer' : 'not-allowed' }}>Add Root</button>
      </div>
    </div>
  );
}
