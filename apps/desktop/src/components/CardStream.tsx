import React from 'react';
import { useEffect, useRef } from 'react';
import { useStore, Card } from '../state/store';
import { MarkdownRenderer } from './MarkdownRenderer';

function MessageCard({ card }: { card: Card }) {
  const isAssistant = card.role === 'assistant';
  return (
    <div style={{
      marginBottom: '1rem',
      padding: '1rem',
      borderRadius: '8px',
      backgroundColor: isAssistant ? '#2d2d30' : '#1e1e1e',
      borderLeft: isAssistant ? '4px solid #007acc' : '4px solid #4caf50',
      color: '#d4d4d4',
      fontFamily: 'sans-serif'
    }}>
      <div style={{ fontSize: '0.8rem', color: '#888', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
        {card.role}
      </div>
      {card.reasoning && (
        <div style={{
          marginBottom: '1rem',
          padding: '0.75rem',
          backgroundColor: '#1e1e1e',
          borderLeft: '2px solid #569cd6',
          fontFamily: 'monospace',
          fontSize: '0.9em',
          color: '#9cdcfe',
          whiteSpace: 'pre-wrap'
        }}>
          {card.reasoning}
        </div>
      )}
      <MarkdownRenderer content={card.content || ""} />
    </div>
  );
}

function FallbackCard({ card }: { card: Card }) {
  return (
    <div style={{ marginBottom: '1rem', padding: '1rem', backgroundColor: '#333', color: '#ccc' }}>
      [{card.type.toUpperCase()}] Not fully implemented in Phase 3 UX yet.
    </div>
  );
}


function ToolCard({ card }: { card: Card }) {
  const isError = card.tool_state === 'error' || card.tool_state === 'denied';
  const isDone = card.tool_state === 'result' || isError;
  const inProgress = !isDone;
  
  return (
    <div style={{
      marginBottom: '1rem',
      padding: '0.75rem',
      borderRadius: '6px',
      backgroundColor: '#252526',
      borderLeft: isError ? '4px solid #f44336' : (inProgress ? '4px solid #ffa726' : '4px solid #4caf50'),
      color: '#d4d4d4',
      fontFamily: 'monospace',
      fontSize: '0.85rem'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
        <strong style={{ color: '#9cdcfe' }}>Tool: {card.tool_name}</strong>
        <span style={{ color: '#888' }}>[{card.tool_state?.toUpperCase()}]</span>
      </div>
      {card.args_preview && (
        <div style={{ color: '#ce9178', marginBottom: '0.5rem' }}>
          &gt; {card.args_preview}
        </div>
      )}
      {card.summary && (
        <div style={{ color: '#888', whiteSpace: 'pre-wrap', maxHeight: '150px', overflowY: 'auto' }}>
          {card.summary}
        </div>
      )}
      {card.reason && isError && (
        <div style={{ color: '#f44336', marginTop: '0.5rem' }}>
          Error: {card.reason}
        </div>
      )}
    </div>
  );
}

function ApprovalCard({ card }: { card: Card }) {
  const backendConfig = useStore(state => state.backendConfig);
  const [armed, setArmed] = React.useState(false);
  
  React.useEffect(() => {
    // 400ms arm delay for destructive/approval actions
    const timer = setTimeout(() => setArmed(true), 400);
    return () => clearTimeout(timer);
  }, []);

  const handleAction = async (action: 'allow' | 'deny', scope: string = 'once') => {
    if (!armed || !backendConfig) return;
    try {
      await fetch(`http://127.0.0.1:${backendConfig.port}/v1/approvals/${card.id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${backendConfig.token}`,
          'Origin': 'http://tauri.localhost'
        },
        body: JSON.stringify({ decision: action, scope_type: scope })
      });
    } catch (e) {
      console.error("Failed to respond to approval:", e);
    }
  };

  if (card.decision) {
    return (
      <div style={{ marginBottom: '1rem', padding: '0.75rem', borderRadius: '6px', backgroundColor: '#333', color: '#888', fontSize: '0.85rem', fontFamily: 'monospace' }}>
        Approval {card.id} resolved as {card.decision.toUpperCase()}.
      </div>
    );
  }

  return (
    <div style={{
      marginBottom: '1rem',
      padding: '1rem',
      borderRadius: '8px',
      backgroundColor: '#2d2d2d',
      borderLeft: '4px solid #ff9800',
      border: '1px solid #555',
      color: '#eee',
      fontFamily: 'sans-serif'
    }}>
      <div style={{ fontSize: '1.1rem', marginBottom: '0.5rem', color: '#ffb74d' }}>
        ⚠️ Requires Approval
      </div>
      <div style={{ marginBottom: '1rem', fontSize: '0.9rem' }}>
        <strong>Action:</strong> {card.action_text || card.tool_name}
        {card.targets && card.targets.length > 0 && (
          <div style={{ marginTop: '0.5rem', fontFamily: 'monospace', color: '#ce9178' }}>
            Targets: {card.targets.join(', ')}
          </div>
        )}
      </div>
      
      <div style={{ display: 'flex', gap: '10px' }}>
        <button 
          onClick={() => handleAction('deny')}
          style={{ padding: '8px 16px', backgroundColor: '#d32f2f', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', flex: 1 }}
        >
          Deny
        </button>
        <button 
          disabled={!armed}
          onClick={() => handleAction('allow')}
          style={{ padding: '8px 16px', backgroundColor: armed ? '#388e3c' : '#555', color: 'white', border: 'none', borderRadius: '4px', cursor: armed ? 'pointer' : 'not-allowed', flex: 1 }}
        >
          {armed ? 'Allow Once' : 'Wait...'}
        </button>
        {card.risk !== 'destructive' && (
          <>
            <button 
              disabled={!armed}
              onClick={() => handleAction('allow', 'session')}
              style={{ padding: '8px 16px', backgroundColor: armed ? '#1976d2' : '#555', color: 'white', border: 'none', borderRadius: '4px', cursor: armed ? 'pointer' : 'not-allowed', flex: 1 }}
            >
              Allow for Session
            </button>
            <button 
              disabled={!armed}
              onClick={() => handleAction('allow', 'always')}
              style={{ padding: '8px 16px', backgroundColor: armed ? '#7b1fa2' : '#555', color: 'white', border: 'none', borderRadius: '4px', cursor: armed ? 'pointer' : 'not-allowed', flex: 1 }}
            >
              Allow Always
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function CardRenderer({ card }: { card: Card }) {
  switch (card.type) {
    case 'message':
      return <MessageCard card={card} />;
    case 'tool':
    case 'denial':
    case 'error':
      return <ToolCard card={card} />;
    case 'approval':
      return <ApprovalCard card={card} />;
    default:
      return <FallbackCard card={card} />;
  }
}

export function CardStream() {
  const cards = useStore(state => state.cards);
  const cardIds = useStore(state => state.cardIds);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [cardIds, cards]);

  return (
    <div
      ref={scrollRef}
      style={{
        flex: 1,
        overflowY: 'auto',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column'
      }}
    >
      {cardIds.map(id => (
        <CardRenderer key={id} card={cards[id]} />
      ))}
    </div>
  );
}
