import { useEffect, useState, useRef } from 'react';
import { useStore } from '../state/store';
import { cancelRun } from '../core/ws';

export function CommandPalette() {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const assistantState = useStore(state => state.assistantState);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen(true);
        setQuery('');
        setSelectedIndex(0);
      }
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  useEffect(() => {
    if (isOpen) {
      inputRef.current?.focus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  // Actions
  const actions = [];

  if (assistantState && !['IDLE', 'ERROR', 'OFFLINE'].includes(assistantState.state) && assistantState.run_id) {
    actions.push({
      id: 'cancel-run',
      label: 'Cancel Active Run',
      action: () => {
        cancelRun(assistantState.run_id!);
        setIsOpen(false);
      }
    });
  }

  actions.push({
    id: 'new-session',
    label: 'New Session',
    action: () => {
      console.log("New session (Phase 3 UI placeholder)");
      setIsOpen(false);
    }
  });

  const filteredActions = actions.filter(a => a.label.toLowerCase().includes(query.toLowerCase()));

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(s => (s + 1) % filteredActions.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(s => (s - 1 + filteredActions.length) % filteredActions.length);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const action = filteredActions[selectedIndex];
      if (action) {
        action.action();
      }
    }
  };

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)', zIndex: 1000,
      display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: '15vh'
    }} onClick={() => setIsOpen(false)}>
      <div
        style={{
          width: '500px', backgroundColor: '#252526', borderRadius: '8px',
          boxShadow: '0 4px 12px rgba(0,0,0,0.5)', display: 'flex', flexDirection: 'column'
        }}
        onClick={e => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={e => { setQuery(e.target.value); setSelectedIndex(0); }}
          onKeyDown={handleKeyDown}
          placeholder="Type a command or search..."
          style={{
            padding: '16px', fontSize: '1rem', backgroundColor: 'transparent',
            border: 'none', borderBottom: '1px solid #333', color: '#fff', outline: 'none'
          }}
        />
        <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
          {filteredActions.map((action, i) => (
            <div
              key={action.id}
              onClick={() => action.action()}
              onMouseEnter={() => setSelectedIndex(i)}
              style={{
                padding: '12px 16px',
                cursor: 'pointer',
                backgroundColor: i === selectedIndex ? '#007acc' : 'transparent',
                color: '#d4d4d4',
              }}
            >
              {action.label}
            </div>
          ))}
          {filteredActions.length === 0 && (
            <div style={{ padding: '12px 16px', color: '#888' }}>No commands found</div>
          )}
        </div>
      </div>
    </div>
  );
}
